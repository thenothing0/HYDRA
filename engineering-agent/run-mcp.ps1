# Stdio MCP launcher: keep stdout reserved for protocol messages.
$projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $projectPython)) {
    Write-Error 'Run setup.ps1 -MCP first.'
    exit 1
}
$env:PATH = "$(Join-Path $PSScriptRoot '.tools\bin');$(Join-Path $PSScriptRoot '.venv\Scripts');$env:PATH"
Push-Location -LiteralPath $PSScriptRoot
try {
    & $projectPython (Join-Path $PSScriptRoot 'mcp_server.py') @args
    $resultCode = $LASTEXITCODE
} finally { Pop-Location }
exit $resultCode
