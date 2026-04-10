# Release Checklist

VaultCLI is still pre-release. When preparing a tagged build, use this checklist:

1. Confirm `main` is green in GitHub Actions.
2. Run `python -m poetry run ruff check .`.
3. Run `python -m poetry run mypy vaultcli`.
4. Run `python -m poetry run pytest --cov=vaultcli --cov-report=term-missing`.
5. Run `python -m poetry build`.
6. Verify the version in `pyproject.toml` and `vaultcli/__init__.py`.
7. Update public documentation if behavior or risk assumptions changed.
8. Create and push a `v*` tag to trigger the release workflow.
