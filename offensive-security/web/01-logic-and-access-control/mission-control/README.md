# MissionControl

**Category:** web / broken access control (privileged header trusted from client) · **Course:** Offensive Security (PoliTo)

## Vulnerability

Authorization level is read from a client-supplied request header (`X-Clearance-Level`) instead of being derived server-side from the authenticated session — the server trusts a value the client can set to anything it wants.

## Exploitation

Intercept a request (e.g. with Burp Suite) and set `X-Clearance-Level: commander`, escalating privileges without any valid credential proving that clearance.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source/handout retained); the original prompt/PDF (`LAB01_logic_vulns.pdf`) covered the full lab.
