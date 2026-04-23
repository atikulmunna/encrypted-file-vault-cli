param(
    [switch]$KeepSmokeArtifacts
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

function Invoke-Step {
    param(
        [Parameter(Mandatory = $true)]
        [string]$Name,
        [Parameter(Mandatory = $true)]
        [scriptblock]$Action
    )

    Write-Host ""
    Write-Host "==> $Name" -ForegroundColor Cyan

    & $Action
    if ($LASTEXITCODE -ne 0) {
        throw "Step failed: $Name"
    }
}

Invoke-Step -Name "Smoke test" -Action {
    if ($KeepSmokeArtifacts) {
        & .\scripts\smoke-test.ps1 -KeepArtifacts
    }
    else {
        & .\scripts\smoke-test.ps1
    }
}

Invoke-Step -Name "Ruff" -Action {
    & python -m poetry run ruff check .
}

Invoke-Step -Name "Mypy" -Action {
    & python -m poetry run mypy vaultcli
}

Invoke-Step -Name "Pytest" -Action {
    & python -m poetry run pytest --cov=vaultcli --cov-report=term-missing
}

Invoke-Step -Name "Build" -Action {
    & python -m poetry build
}

Write-Host ""
Write-Host "Release check passed." -ForegroundColor Green
