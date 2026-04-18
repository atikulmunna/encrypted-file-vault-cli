# Usage Guide

VaultCLI is designed around a small set of repeatable workflows. This guide keeps the copy-paste paths in one place so new users do not need to piece them together from help output and release notes.

## Development Run Mode

During local development, run the CLI through Poetry:

```powershell
python -m poetry run vault --help
```

If you install the package directly, the entrypoint is:

```powershell
vault --help
```

## Create A Vault

Prompt for a passphrase interactively:

```powershell
python -m poetry run vault create secrets.vault
```

Provide a passphrase directly:

```powershell
python -m poetry run vault create secrets.vault --passphrase "CorrectHorseBatteryStaple123!"
```

Use an environment variable:

```powershell
$env:VAULTCLI_PASSPHRASE = "CorrectHorseBatteryStaple123!"
python -m poetry run vault create secrets.vault --passphrase-env VAULTCLI_PASSPHRASE
```

Use a UTF-8 passphrase file:

```powershell
python -m poetry run vault create secrets.vault --passphrase-file .\passphrase.txt
```

## Inspect A Vault

Read public metadata without unlocking:

```powershell
python -m poetry run vault info secrets.vault
```

Read authenticated metadata:

```powershell
python -m poetry run vault info secrets.vault --prompt-passphrase
```

List stored files:

```powershell
python -m poetry run vault list secrets.vault --prompt-passphrase
```

## Add Files And Directories

Add one file:

```powershell
python -m poetry run vault add secrets.vault .\notes.txt --prompt-passphrase
```

Add a directory tree:

```powershell
python -m poetry run vault add secrets.vault .\project-files --prompt-passphrase
```

## Extract Files

Extract one stored path:

```powershell
python -m poetry run vault extract secrets.vault notes.txt --prompt-passphrase --output .\restore
```

Extract the full vault contents:

```powershell
python -m poetry run vault extract secrets.vault --all --prompt-passphrase --output .\restore
```

Overwrite existing output files deliberately:

```powershell
python -m poetry run vault extract secrets.vault --all --prompt-passphrase --output .\restore --overwrite
```

## Verify And Rekey

Run locked structural verification:

```powershell
python -m poetry run vault verify secrets.vault --locked
```

Run authenticated verification:

```powershell
python -m poetry run vault verify secrets.vault --prompt-passphrase
```

Change the outer passphrase:

```powershell
python -m poetry run vault rekey secrets.vault --current-passphrase-env VAULTCLI_OLD_PASS --new-passphrase-file .\new-passphrase.txt
```

## Hidden Volume Workflows

Create a hidden region:

```powershell
python -m poetry run vault hidden create secrets.vault --hidden-size 1048576 --outer-passphrase-env VAULTCLI_OUTER_PASS --inner-passphrase-file .\hidden-passphrase.txt
```

List hidden files:

```powershell
python -m poetry run vault hidden list secrets.vault --outer-passphrase-env VAULTCLI_OUTER_PASS --inner-passphrase-file .\hidden-passphrase.txt
```

Add a hidden file:

```powershell
python -m poetry run vault hidden add secrets.vault .\inner.txt --outer-passphrase-env VAULTCLI_OUTER_PASS --inner-passphrase-file .\hidden-passphrase.txt
```

Extract hidden contents:

```powershell
python -m poetry run vault hidden extract secrets.vault --all --outer-passphrase-env VAULTCLI_OUTER_PASS --inner-passphrase-file .\hidden-passphrase.txt --output .\hidden-restore
```

Verify the hidden volume:

```powershell
python -m poetry run vault hidden verify secrets.vault --outer-passphrase-env VAULTCLI_OUTER_PASS --inner-passphrase-file .\hidden-passphrase.txt
```

## Common Notes

- `vault info` works without a passphrase in locked mode, but `vault list` always requires authenticated access.
- `vault verify --locked` checks container structure only. Use authenticated verification for file-level integrity checks.
- `vault extract` refuses to overwrite existing files unless `--overwrite` is supplied.
- Hidden-volume commands require both the outer and inner passphrases.
- Using `--passphrase-env` or `--passphrase-file` is safer than putting secrets directly into shell history.
