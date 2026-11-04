# TicketVault

**Category:** web / broken access control (IDOR) · **Course:** Offensive Security (PoliTo)

## Vulnerability

Support tickets are retrievable by a sequential, guessable ticket number with no ownership/authorization check tying the requester to that specific ticket — the same IDOR pattern as LabResults, applied to a different resource.

## Exploitation

Using Burp Suite, request ticket number `1` directly while authenticated as an unprivileged account and read its (unauthorized) contents.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source/handout retained); the original prompt/PDF (`LAB01_logic_vulns.pdf`) covered the full lab.
