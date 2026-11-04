# NeonArcade

**Category:** web / broken access control (client-trusted role parameter) · **Course:** Offensive Security (PoliTo)

## Vulnerability

The account settings request includes a `role` parameter that the backend accepts as authoritative, without checking whether the currently authenticated user is actually permitted to change it.

## Exploitation

Intercept the settings request (Burp Suite) and add/modify the parameter to `role=admin` before forwarding it — the server applies the change with no server-side authorization check.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained). This challenge sat alongside the KeyVault JWT challenge in the same lab (`web02`).
