# LabResults

**Category:** web / broken access control (IDOR) · **Course:** Offensive Security (PoliTo)

## Vulnerability

Lab report records are accessed by a predictable, sequential identifier in the URL (`/report/1`, etc.) with no check that the requesting user actually owns or is authorized to view that specific record — a classic Insecure Direct Object Reference (IDOR).

## Exploitation

Request another user's report directly by its ID (`/1`) while authenticated as a different, unprivileged account. The endpoint returns the data with no ownership check.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source/handout retained); the original prompt/PDF (`LAB01_logic_vulns.pdf`) covered the full lab.
