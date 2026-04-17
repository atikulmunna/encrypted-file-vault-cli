# Release Notes Template

Use this template when preparing a tagged release or release candidate.

## Summary

One short paragraph describing the purpose of the release.

## Highlights

- major feature or workflow addition
- important hardening or compatibility improvement
- notable documentation or packaging change

## Security Notes

- important caveats that still apply
- changes that improve integrity, parsing, or operational safety
- any hidden-volume or wipe-related caution worth repeating

## Testing

- `python -m poetry run ruff check .`
- `python -m poetry run mypy vaultcli`
- `python -m poetry run pytest --cov=vaultcli --cov-report=term-missing`
- `python -m poetry build`

## Compatibility Notes

- note any behavior changes
- call out command-line changes if flags or outputs changed
- mention platform caveats if relevant

## Known Limits

- list the main pre-release limits that still remain
- keep this short and concrete
