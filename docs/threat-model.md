# Threat Model

VaultCLI aims to protect file contents and authenticated metadata inside a portable encrypted container while keeping the operational model simple enough to inspect and test.

## Security Goals

- protect stored file contents against offline disclosure without the correct passphrase
- authenticate the encrypted index and encrypted file chunks so tampering is detected
- avoid writing plaintext temporary files during normal vault operations
- support scriptable and interactive passphrase input paths without changing the core container model
- keep the container format explicit and reviewable

## Assumptions

- the attacker may obtain a copy of the vault file
- the attacker may modify, truncate, or bit-flip bytes in the container
- the attacker does not already control the system while the vault is actively unlocked and in use
- the operating system, Python runtime, filesystem, and storage stack may have behaviors that limit secure deletion or memory-clearing guarantees

## Out of Scope

- protection against a fully compromised host while a user is entering passphrases or handling plaintext
- protection against hardware keyloggers, hostile kernel components, or malicious endpoint agents
- guaranteed plausible deniability properties for hidden volumes without deeper external review
- guaranteed secure deletion on SSDs, flash storage, snapshots, or journaling filesystems
- protection against side-channel attacks beyond what is normally provided by the underlying cryptographic libraries

## Hidden Volume Notes

VaultCLI includes hidden-volume workflows, but the security interpretation of those workflows should remain conservative. The implementation tries to avoid obvious metadata disclosure in the public header, but hidden-volume deniability should still be treated as provisional until the format, threat model, and operational caveats receive stronger review.

## Integrity Model

- the outer encrypted index is authenticated
- hidden encrypted indexes are authenticated
- file chunks are authenticated individually
- structural corruption in the container layout should fail parsing or verification
- authenticated verification only covers the meaningful encrypted data and metadata, not arbitrary random padding that exists only to fill reserved space

## Operational Caveats

- plaintext can still exist in process memory, shell history, editor buffers, crash dumps, swap, or filesystem caches outside the direct control of VaultCLI
- passphrase strength remains a practical limit on offline attack resistance
- wiping files after extraction is best-effort only and depends on the platform and storage implementation

## Practical Reading

The safest current way to interpret VaultCLI is:

- good for implementation study and non-sensitive evaluation
- promising for a portable encrypted container workflow
- not yet a reviewed security product suitable for high-risk secrets
