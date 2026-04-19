param(
    [switch]$KeepArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Vault {
    param(
        [Parameter(Mandatory = $true)]
        [string[]]$Arguments
    )

    Write-Host ""
    Write-Host "==> vault $($Arguments -join ' ')" -ForegroundColor Cyan

    & python -m poetry run vault @Arguments
    if ($LASTEXITCODE -ne 0) {
        throw "Vault command failed with exit code $LASTEXITCODE."
    }
}

function Assert-FileContent {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Path,
        [Parameter(Mandatory = $true)]
        [string]$Expected
    )

    if (-not (Test-Path -LiteralPath $Path)) {
        throw "Expected file was not created: $Path"
    }

    $actual = Get-Content -LiteralPath $Path -Raw
    if ($actual -ne $Expected) {
        throw "Unexpected file content in $Path"
    }
}

$root = Join-Path -Path ([System.IO.Path]::GetTempPath()) -ChildPath ("vaultcli-smoke-" + [guid]::NewGuid().ToString("N"))
New-Item -ItemType Directory -Path $root | Out-Null

$outerPassphrase = "OuterSmokePassphrase123!"
$innerPassphrase = "InnerSmokePassphrase123!"
$env:VAULTCLI_SMOKE_OUTER_PASS = $outerPassphrase
$env:VAULTCLI_SMOKE_INNER_PASS = $innerPassphrase

try {
    $vaultPath = Join-Path -Path $root -ChildPath "smoke.vault"
    $outerSource = Join-Path -Path $root -ChildPath "notes.txt"
    $outerRestore = Join-Path -Path $root -ChildPath "restore"
    $hiddenSource = Join-Path -Path $root -ChildPath "inner.txt"
    $hiddenRestore = Join-Path -Path $root -ChildPath "hidden-restore"

    Set-Content -LiteralPath $outerSource -Value "hello vault smoke test" -Encoding utf8
    Set-Content -LiteralPath $hiddenSource -Value "hello hidden smoke test" -Encoding utf8

    Invoke-Vault @(
        "create",
        $vaultPath,
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS"
    )
    Invoke-Vault @(
        "add",
        $vaultPath,
        $outerSource,
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS"
    )
    Invoke-Vault @(
        "list",
        $vaultPath,
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS"
    )
    Invoke-Vault @("info", $vaultPath)
    Invoke-Vault @(
        "info",
        $vaultPath,
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS"
    )
    Invoke-Vault @("verify", $vaultPath, "--locked")
    Invoke-Vault @(
        "verify",
        $vaultPath,
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS"
    )
    Invoke-Vault @(
        "extract",
        $vaultPath,
        "notes.txt",
        "--passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--output", $outerRestore
    )

    Assert-FileContent -Path (Join-Path -Path $outerRestore -ChildPath "notes.txt") -Expected "hello vault smoke test`r`n"

    Invoke-Vault @(
        "hidden",
        "create",
        $vaultPath,
        "--hidden-size", "4096",
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS"
    )
    Invoke-Vault @(
        "hidden",
        "add",
        $vaultPath,
        $hiddenSource,
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS"
    )
    Invoke-Vault @(
        "hidden",
        "list",
        $vaultPath,
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS"
    )
    Invoke-Vault @(
        "hidden",
        "info",
        $vaultPath,
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS"
    )
    Invoke-Vault @(
        "hidden",
        "verify",
        $vaultPath,
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS"
    )
    Invoke-Vault @(
        "hidden",
        "extract",
        $vaultPath,
        "inner.txt",
        "--outer-passphrase-env", "VAULTCLI_SMOKE_OUTER_PASS",
        "--inner-passphrase-env", "VAULTCLI_SMOKE_INNER_PASS",
        "--output", $hiddenRestore
    )

    Assert-FileContent -Path (Join-Path -Path $hiddenRestore -ChildPath "inner.txt") -Expected "hello hidden smoke test`r`n"

    Write-Host ""
    Write-Host "Smoke test passed." -ForegroundColor Green
    Write-Host "Artifacts directory: $root"
}
finally {
    Remove-Item Env:VAULTCLI_SMOKE_OUTER_PASS -ErrorAction SilentlyContinue
    Remove-Item Env:VAULTCLI_SMOKE_INNER_PASS -ErrorAction SilentlyContinue

    if (-not $KeepArtifacts -and (Test-Path -LiteralPath $root)) {
        Remove-Item -LiteralPath $root -Recurse -Force
    }
}
