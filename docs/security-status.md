# Security Status

VaultCLI is an actively developed security-oriented project. The current codebase implements the planned core workflows, but the repository should still be treated as pre-release software under hardening.

## What Is Implemented

- Argon2id-based passphrase key derivation
- AES-GCM encryption for wrapped keys, encrypted indexes, and file chunks
- single-container outer vault format
- hidden-volume creation and file workflows
- authenticated verify flows for outer and hidden volumes
- metadata-first read paths to reduce unnecessary whole-payload loading
- CI, packaging, linting, typing, and repeatable local test workflows

## What Is Stronger Than Before

- parser hardening coverage for malformed headers, index sizes, and hidden-region corruption
- larger end-to-end workflow coverage for directory trees and mixed outer/hidden usage
- clearer internal separation between vault service orchestration, data models, and ciphertext helpers
- better CLI validation for conflicting or missing passphrase sources

## Current Limits

- no external security review has been completed yet
- hidden-volume deniability properties have not been independently validated
- secure deletion is best-effort only and depends heavily on the underlying storage stack
- this project does not promise complete in-memory secret eradication under Python runtime behavior
- more adversarial, fuzz-style, and cross-platform stress testing is still warranted

## Recommended Use Right Now

- local experimentation with non-sensitive data
- implementation review
- educational reference for encrypted container design tradeoffs
- CI and packaging validation

## Not Yet Recommended

- production protection of high-value secrets
- sole backup location for confidential or irreplaceable data
- environments that require audited deniability guarantees

## Release Readiness Direction

Before calling VaultCLI a stronger release candidate, the project should complete:

- broader parser and corruption fuzzing
- more long-running and large-dataset stress testing
- deeper documentation of threat model and non-goals
- explicit platform caveats for wipe and filesystem behavior
- external review of cryptographic and hidden-volume assumptions
