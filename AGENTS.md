# Release Workflow

## 1. Build & Push Code Changes

```powershell
dotnet build -c Release .\LoaderKeyed.csproj
git add <files> -A
git commit -m "description of changes"
git push
```

## 2. Update release.zip on GitHub Releases

### A. Build clean Release and create zip

```powershell
# Kill any running instance first (close app manually)
dotnet clean .\LoaderKeyed.csproj -c Release
dotnet build -c Release .\LoaderKeyed.csproj

# Create release.zip (exclude .pdb files)
if (Test-Path '.\release.zip') { Remove-Item '.\release.zip' }
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    (Resolve-Path '.\bin\Release\net8.0-windows7.0').Path,
    (Resolve-Path '.').Path + '\release.zip',
    [System.IO.Compression.CompressionLevel]::Optimal, $false)
```

### B. Get GitHub token from Windows Credential Manager

```powershell
$token = ((("protocol=https`nhost=github.com`n") | git credential fill 2>$null) -split "`n" |
    Where-Object { $_ -match '^password=' } |
    ForEach-Object { $_ -replace '^password=', '' })
$headers = @{ Authorization = "token $token" }
```

### C. Delete old Release tag and recreate at HEAD

```powershell
git tag -d Release
git push origin --delete Release
git tag Release HEAD
git push origin Release
```

### D. Update the release asset

```powershell
# Get release ID
$release = Invoke-RestMethod -Uri "https://api.github.com/repos/Trapwithme/Trap-Panel/releases/tags/Release" -Headers $headers
$releaseId = $release.id

# Delete old assets
foreach ($asset in $release.assets) {
    Invoke-RestMethod -Uri $asset.url -Headers $headers -Method DELETE
}

# Upload new release.zip
$zipBytes = [System.IO.File]::ReadAllBytes((Resolve-Path '.\release.zip').Path)
$uploadHeaders = $headers.Clone()
$uploadHeaders["Content-Type"] = "application/x-zip-compressed"
Invoke-RestMethod -Uri "https://uploads.github.com/repos/Trapwithme/Trap-Panel/releases/$releaseId/assets?name=Release.zip" `
    -Headers $uploadHeaders -Method POST -Body $zipBytes

# Publish release (fixes draft state)
$body = @{ draft = $false; tag_name = "Release"; target_commitish = "main" } | ConvertTo-Json
Invoke-RestMethod -Uri "https://api.github.com/repos/Trapwithme/Trap-Panel/releases/$releaseId" `
    -Headers $headers -Method PATCH -Body $body
```

## 3. Update release.zip in git (optional, for repo file)

```powershell
git add -f release.zip
git commit -m "Update release.zip"
git push
```
