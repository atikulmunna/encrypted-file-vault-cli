# Release Candidate Status

VaultCLI is not a tagged release candidate yet, but it is no longer in the initial implementation phase either.

## Current State

- core planned command workflows are implemented
- hidden-volume workflows are implemented
- metadata-first read paths and streaming-oriented improvements are in place
- parser, corruption, CLI failure-path, stress, and platform-oriented tests are present
- reviewer-facing documentation now exists for threat model, security posture, audit prep, and release prep

## What Looks Ready

- basic command surface for outer and hidden workflows
- local development and CI verification flow
- packaging to wheel and sdist
- build-in-public reviewer handoff documentation

## What Still Blocks A Stronger RC Claim

- no external security review or audit has been completed
- hidden-volume deniability properties still need conservative treatment
- more adversarial fuzzing and long-running stress coverage would still add value
- final issue tracker triage and release notes need to match the current state exactly

## Recommended Next RC Steps

1. Close or relabel completed implementation issues.
2. Open a smaller post-backlog set of hardening and RC-prep issues.
3. Prepare draft release notes for the first release candidate.
4. Re-run the release checklist on a clean tree.
5. Decide whether the next tag should be `0.1.0-rc1` or stay untagged until external review input lands.

## Conservative Read

Today, VaultCLI is best described as:

- feature-complete for the currently intended v1 engineering slice
- substantially hardened compared with the initial backlog phase
- still pre-release from a security assurance perspective
