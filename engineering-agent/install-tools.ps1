# Install official Windows binaries locally, validating publisher SHA-256 hashes.
[CmdletBinding()]
param([string[]]$Names = @('subfinder', 'httpx', 'nuclei', 'katana', 'ffuf', 'gau'))
$ErrorActionPreference = 'Stop'
$repositories = @{
    subfinder = 'projectdiscovery/subfinder'; httpx = 'projectdiscovery/httpx'
    nuclei = 'projectdiscovery/nuclei'; katana = 'projectdiscovery/katana'
    ffuf = 'ffuf/ffuf'; gau = 'lc/gau'
}
$toolsRoot = Join-Path $PSScriptRoot '.tools'
$binDir = Join-Path $toolsRoot 'bin'
$cacheDir = Join-Path $toolsRoot 'downloads'
New-Item -ItemType Directory -Force -Path $binDir, $cacheDir | Out-Null
Add-Type -AssemblyName System.IO.Compression.FileSystem
foreach ($name in $Names) {
    if (-not $repositories.ContainsKey($name)) { throw "Unknown tool: $name" }
    $manifestPath = Join-Path $toolsRoot "$name.json"
    $binaryPath = Join-Path $binDir "$name.exe"
    if ((Test-Path -LiteralPath $manifestPath) -and (Test-Path -LiteralPath $binaryPath)) {
        $installed = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
        if ((Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash -eq $installed.binary_sha256) {
            Write-Host "$name already installed and verified ($($installed.version))"
            continue
        }
    }
    $repo = $repositories[$name]
    Write-Host "Resolving official release: $repo"
    $release = Invoke-RestMethod -Uri "https://api.github.com/repos/$repo/releases/latest" -Headers @{'User-Agent'='HYDRA-local-setup'} -TimeoutSec 30
    $assets = @($release.assets | Where-Object { $_.name -match '(?i)windows[_-](amd64|x86_64).*\.zip$' })
    if ($assets.Count -ne 1) { throw "Expected one Windows x64 archive for $name" }
    $asset = $assets[0]
    $archivePath = Join-Path $cacheDir $asset.name
    $checksums = @($release.assets | Where-Object { $_.name -match '(?i)checksums.*\.txt$' })
    if ($checksums.Count -ne 1) { throw "No unambiguous publisher checksum file for $name" }
    $checksumText = (Invoke-WebRequest -Uri $checksums[0].browser_download_url -UseBasicParsing -TimeoutSec 30).Content
    if ($checksumText -is [byte[]]) { $checksumText = [Text.Encoding]::UTF8.GetString($checksumText) }
    $pattern = '(?im)^([a-f0-9]{64})\s+\*?' + [regex]::Escape($asset.name) + '\s*$'
    $match = [regex]::Match($checksumText, $pattern)
    if (-not $match.Success) { throw "Missing SHA256 entry for $($asset.name)" }
    $expectedHash = $match.Groups[1].Value
    if (-not (Test-Path -LiteralPath $archivePath)) {
        Write-Host "Downloading $($asset.name) ($([math]::Round($asset.size / 1MB, 1)) MB)"
        Invoke-WebRequest -Uri $asset.browser_download_url -OutFile $archivePath -UseBasicParsing -TimeoutSec 600
    }
    if ((Get-FileHash -LiteralPath $archivePath -Algorithm SHA256).Hash -ne $expectedHash) {
        throw "Checksum mismatch for $archivePath. Remove this archive and retry."
    }
    # Extract only the named executable; never trust archive paths.
    $zip = [IO.Compression.ZipFile]::OpenRead($archivePath)
    try {
        $entries = @($zip.Entries | Where-Object { $_.Name -eq "$name.exe" })
        if ($entries.Count -ne 1) { throw "Expected one $name.exe in the verified archive" }
        [IO.Compression.ZipFileExtensions]::ExtractToFile($entries[0], $binaryPath, $true)
    } finally { $zip.Dispose() }
    @{
        tool=$name; version=$release.tag_name; repository=$repo
        archive_sha256=$expectedHash; download_url=$asset.browser_download_url
        binary_sha256=(Get-FileHash -LiteralPath $binaryPath -Algorithm SHA256).Hash
    } | ConvertTo-Json | Set-Content -LiteralPath $manifestPath -Encoding UTF8
    Write-Host "Installed and verified $name $($release.tag_name)"
}
