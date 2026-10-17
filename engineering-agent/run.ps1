# Forward arguments verbatim to the project-local Python CLI.
$projectPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $projectPython)) {
    Write-Error 'Run setup.ps1 first to create the project environment.'
    exit 1
}
$env:PATH = "$(Join-Path $PSScriptRoot '.tools\bin');$(Join-Path $PSScriptRoot '.venv\Scripts');$env:PATH"
Push-Location -LiteralPath $PSScriptRoot
try {
    & $projectPython -m hydra @args
    $resultCode = $LASTEXITCODE
} finally { Pop-Location }
exit $resultCode
