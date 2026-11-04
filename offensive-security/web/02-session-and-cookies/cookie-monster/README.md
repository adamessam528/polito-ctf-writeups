# CookieMonster

**Category:** web / weak session management (unsigned, base64-only cookie) · **Course:** Offensive Security (PoliTo)

## Vulnerability

The session cookie is just base64-encoded JSON (or similar) with no signature or encryption (no HMAC, no JWT signing) — anything the client can decode, it can also re-encode and send back, including fields that should be server-authoritative like a role/privilege flag.

## Exploitation

1. Decode the session cookie from base64 to see its structure.
2. Edit the decoded contents to set the role/privilege field to `admin`.
3. Re-encode to base64 and replace the cookie — the server trusts it as-is since there's no signature to invalidate.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
