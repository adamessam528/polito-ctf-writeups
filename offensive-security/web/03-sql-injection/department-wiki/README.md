# Department Wiki

**Category:** web / SQL injection (stacked query, data relocation) · **Course:** Offensive Security (PoliTo)

## Challenge

A small internal wiki (Express + `better-sqlite3`) storing departments, articles, a revision log, and an `internal_config` key/value table. The flag is seeded into `internal_config` under the key `admin_token` — a table that isn't normally rendered anywhere in the UI.

## Vulnerability

Wherever the wiki builds a SQL query from user input, it's vulnerable to injection that permits **stacked (piggy-backed) statements** — i.e. `; <second statement>` — rather than only single-statement UNION injection. That's a stronger primitive than the other SQLi challenges in this set: instead of only reading data via a `SELECT` you control the shape of, you can run an entirely separate write statement.

## Exploitation

Since `internal_config` is never displayed by any page, the trick is to **exfiltrate by relocating the secret into a table that is rendered** — the public `departments` list — using a stacked `INSERT`:

```sql
'; INSERT INTO departments(name) SELECT value FROM internal_config WHERE key='admin_token';--
```

This closes the original string literal, appends a brand-new `INSERT ... SELECT` that copies `admin_token`'s value into a new department's `name` field, and comments out the rest of the original query. Browsing the department list afterward shows the flag in plain sight.

## Files

- `app.js` — challenge server source (Express + better-sqlite3), showing the `internal_config` table and seed data the injection targets

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
