# Security policy

npryx is a security tool, so reports are especially welcome.

## Reporting a vulnerability

Please report privately, not in a public issue:

- **GitHub:** use "Report a vulnerability" on the repository's Security tab (private
  vulnerability reporting).
- **Email:** lachlan.jacobs@protonmail.com

Include what you found, how to reproduce it, and what an attacker could do with it. I aim
to acknowledge reports within a few days and will keep you updated until it's fixed. With
your permission, you'll be credited in the release notes.

## Scope

- The `npryx` CLI: anything that lets a package run without the preview or the user's
  decision, defeats the fail-closed behaviour, or bypasses the trust store.
- `scan-service/` (npryx-scan): signature or cache bypasses, ways to make a result clear a
  warning, sandbox escapes, and anything that leaks a user's data.

## Supported versions

Only the latest release is supported.
