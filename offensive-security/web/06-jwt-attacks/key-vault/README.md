# KeyVault

**Category:** web / JWT `jku` (JWK Set URL) header injection → authentication bypass · **Course:** Offensive Security (PoliTo)

## Challenge

An authentication service issues and verifies RS256-signed JWTs. RS256 verification needs the server to know which *public* key to check the signature against — this service resolves that key by trusting a `jku` (JWK Set URL) header embedded in the token itself, fetching whatever JWKS document that URL points to.

## Vulnerability

`jku` header injection. The JWT spec allows a token to advertise, via its own `jku` header, where the verifier should fetch the public key from. If the verifier doesn't restrict `jku` to a fixed, trusted origin (e.g. its own `/.well-known/jwks.json`), an attacker can:

1. Generate their own RSA keypair.
2. Host the public half as a valid-looking JWKS document at a URL they control.
3. Forge a JWT signed with their private key, claiming any identity/role they like, with `jku` pointing at their self-hosted JWKS.

Since RS256 verification only checks "does this signature match the key the `jku` URL provides" — and never asks "is this `jku` URL one I actually trust" — the server ends up verifying the attacker's forged token against the attacker's own key, and accepts it.

## Exploitation

1. Generate an RSA keypair locally (`private.pem` / `public.pem`).
2. Build a JWKS document from the public key, matching the `kid` the verifier expects, and publish it somewhere fetchable over HTTPS (in this solve, GitHub Pages) — `generate_jwks.py`.
3. Forge a token with the desired claims and a `jku` header pointing at that hosted JWKS, signed with the matching private key:

   ```python
   payload = {"sub": "adam", "user_id": 4, "role": "admin", "iat": ..., "exp": ...}
   headers = {
       "alg": "RS256",
       "jku": "https://ATTACKER-SERVER/jwks.json",
       "kid": "052954d043c467a6",
       "typ": "JWT",
   }
   token = jwt.encode(payload, private_key, algorithm="RS256", headers=headers)
   ```

4. Present the forged token to the service — it fetches the attacker's JWKS via `jku`, verifies the signature successfully against the attacker's own public key, and accepts `role: admin`.

## Files

- `solve.py` — forges the RS256 JWT with a malicious `jku` header
- `generate_jwks.py` — builds a JWKS document from the local public key for hosting
- `private.pem` / `public.pem` — the attacker-generated RSA keypair used for the forgery (not a secret belonging to the target service — this is the exploit's own key material)
- `jwks.json` — the JWKS document that was published and referenced by the forged token's `jku` header

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Mitigation (for the write-up's own sake)

Verifiers should never resolve signing keys from a URL embedded in the token being verified. `jku` (and the related `x5u`) should either be disabled entirely or restricted to an allow-list of trusted origins resolved server-side, independent of anything the token itself claims.
