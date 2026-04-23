Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$lines = @(
    '██    ██  █████  ██    ██ ██   ████████      ██████ ██      ██',
    '██    ██ ██   ██ ██    ██ ██      ██        ██      ██      ██',
    '██    ██ ███████ ██    ██ ██      ██        ██      ██      ██',
    ' ██  ██  ██   ██ ██    ██ ██      ██        ██      ██      ██',
    '  ████   ██   ██  ██████  ███████ ██         ██████ ███████ ██',
    '',
    '        Encrypted File Vault CLI',
    '        Outer + Hidden Volume Workflows',
    '        AES-256-GCM  |  Argon2id  |  Offline First'
)

Write-Host ''
foreach ($line in $lines[0..4]) {
    Write-Host $line -ForegroundColor Cyan
}
Write-Host ''
Write-Host $lines[6] -ForegroundColor White
Write-Host $lines[7] -ForegroundColor DarkGray
Write-Host $lines[8] -ForegroundColor DarkGray
Write-Host ''
