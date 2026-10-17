# HYDRA Windows setup. Installs into a project-local environment.
[CmdletBinding()]
param(
    [string]$PythonExecutable,
    [switch]$Full,
    [switch]$MCP,
    [switch]$Providers,
    [switch]$InstallTools,
    [switch]$SkipTests
)
$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

function Invoke-Checked {
    param([string]$Program, [string[]]$Arguments)
    & $Program @Arguments
    if ($LASTEXITCODE -ne 0) { throw "Command failed (exit $LASTEXITCODE): $Program $Arguments" }
}

if (-not $PythonExecutable) {
    $candidates = @('python', 'py')
    if ($env:LOCALAPPDATA) {
        $candidates += @(Get-ChildItem -Path "$env:LOCALAPPDATA\Programs\Python\Python*\python.exe" -ErrorAction SilentlyContinue | ForEach-Object FullName)
    }
    foreach ($candidate in $candidates) {
        try {
            & $candidate -c 'import sys; assert sys.version_info >= (3, 10)' 2>$null
            if ($LASTEXITCODE -eq 0) { $PythonExecutable = $candidate; break }
        } catch { }
    }
}
if (-not $PythonExecutable) { throw 'Python 3.10+ was not found. Pass -PythonExecutable with its full path.' }
Invoke-Checked $PythonExecutable @('-c', 'import sys; assert sys.version_info >= (3, 10)')
if (-not (Test-Path -LiteralPath '.venv\Scripts\python.exe')) {
    Invoke-Checked $PythonExecutable @('-m', 'venv', '.venv')
}
$projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements-agent.txt')
if ($Full) { Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements.txt') }
if ($Providers) { Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements-providers.txt') }
if ($MCP) {
    Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements-mcp.txt')
    $mcpSettings = @{mcpServers = @{'hydra-security' = @{
        command = $projectPython
        args = @((Join-Path $PSScriptRoot 'mcp_server.py'))
        env = @{PATH = "$(Join-Path $PSScriptRoot '.tools\bin');$(Join-Path $PSScriptRoot '.venv\Scripts');$env:PATH"}
    }}}
    $mcpSettings | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath '.mcp.local.json' -Encoding UTF8
}
if (-not (Test-Path -LiteralPath '.env')) { Copy-Item -LiteralPath '.env.example' -Destination '.env' }
$env:PATH = "$(Join-Path $PSScriptRoot '.tools\bin');$(Join-Path $PSScriptRoot '.venv\Scripts');$env:PATH"
if ($InstallTools) {
    Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements-tools.txt')
    & (Join-Path $PSScriptRoot 'install-tools.ps1')
}
Invoke-Checked $projectPython @('-m', 'pip', 'check')
if (-not $SkipTests) {
    Invoke-Checked $projectPython @('-m', 'pip', 'install', '-r', 'requirements-dev.txt')
    Invoke-Checked $projectPython @('-m', 'pytest', 'tests', '-q')
}
Invoke-Checked $projectPython @('-m', 'hydra.main', '--check-tools')
Write-Host 'HYDRA local setup complete. Missing external tools are listed above.' -ForegroundColor Green
Write-Host 'Run: .\run.ps1'
Write-Host 'Provider keys go in .env. Ollama/models and Burp Suite + its MCP extension are separate applications.'
Write-Host 'Network scans require installed tools and --scope-file <authorized-scope.json>.'
