# AlDente

**Category:** web / broken access control (privilege escalation via profile field) · **Course:** Offensive Security (PoliTo)

## Vulnerability

The user profile lets the client set their own `role` field, and the backend trusts it without an authorization check against what a self-service profile update should be allowed to change.

## Exploitation

Edit the profile and set the role to `head chef` (an admin-tier role) directly — the server accepts the client-supplied value with no server-side check that a regular user isn't allowed to grant themselves elevated privileges.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source/handout retained); the original prompt/PDF (`LAB01_logic_vulns.pdf`) covered the full lab.
