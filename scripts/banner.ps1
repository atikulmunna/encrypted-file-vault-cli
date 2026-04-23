Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$lines = @(
    ' __      __         _ _   _____ _      _____ ',
    ' \ \    / /        | | | / ____| |    |_   _|',
    '  \ \  / /_ _ _   _| | || |    | |      | |  ',
    '   \ \/ / _` | | | | | || |    | |      | |  ',
    '    \  / (_| | |_| | | || |____| |____ _| |_ ',
    '     \/ \__,_|\__,_|_|_| \_____|______|_____|',
    '',
    '     Encrypted File Vault CLI',
    '     Outer + Hidden Volume Workflows',
    '     AES-256-GCM  |  Argon2id  |  Offline First'
)

Write-Host ""
foreach ($line in $lines[0..5]) {
    Write-Host $line -ForegroundColor Cyan
}
Write-Host ""
Write-Host $lines[7] -ForegroundColor White
Write-Host $lines[8] -ForegroundColor DarkGray
Write-Host $lines[9] -ForegroundColor DarkGray
Write-Host ""
