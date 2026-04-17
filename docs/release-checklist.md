# Release Checklist

VaultCLI is still pre-release. Use this checklist before calling any build a release candidate or tagging a public version.

## Release-Candidate Gate

All of the following should be true:

1. `main` is green in GitHub Actions.
2. The working tree is clean except for intentionally version-bumped files.
3. Public documentation matches the current command surface and risk posture.
4. No known high-severity correctness or corruption bugs remain open for the tagged slice.

## Local Verification

Run all of the following locally:

1. `python -m poetry run ruff check .`
2. `python -m poetry run mypy vaultcli`
3. `python -m poetry run pytest --cov=vaultcli --cov-report=term-missing`
4. `python -m poetry build`

## Documentation Review

Before a tag:

1. Review [README.md](../README.md).
2. Review [docs/security-status.md](security-status.md).
3. Review [docs/threat-model.md](threat-model.md).
4. Review [docs/audit-prep.md](audit-prep.md).
5. Update caveats if behavior, non-goals, or security assumptions changed.

## Release Metadata

Before creating a tag:

1. Verify the version in `pyproject.toml`.
2. Verify the version in `vaultcli/__init__.py`.
3. Prepare concise release notes using [docs/release-notes-template.md](release-notes-template.md).
4. Make sure the notes summarize:
   - major user-facing changes
   - security caveats that still apply
   - any migration or compatibility notes

## Tagging

When the checklist is satisfied:

1. Create a `v*` tag on the intended commit.
2. Push the tag to trigger the release workflow.
3. Confirm the generated wheel and sdist artifacts were produced successfully.

## Not a Release Candidate If

Do not tag a release candidate if any of these are still true:

1. tests pass only on one machine but not in CI
2. public docs disagree with implemented behavior
3. threat-model caveats changed but were not documented
4. parser hardening or corruption regressions are still under investigation
