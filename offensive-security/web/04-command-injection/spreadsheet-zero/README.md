# SpreadsheetZero

**Category:** web / formula injection → server-side code execution · **Course:** Offensive Security (PoliTo)

## Challenge

A minimal spreadsheet-style app that evaluates cell contents starting with `=` as formulas — echoing the classic "CSV/spreadsheet formula injection" bug class, but here the formula engine turns out to be backed by real Python evaluation rather than a safe expression parser.

## Vulnerability

Cell formulas are evaluated with something equivalent to Python's `eval()`, with no sandboxing against dangerous builtins like `__import__`. That turns a "spreadsheet formula" field into a full Python code execution primitive.

## Exploitation

1. Fingerprint the environment first, confirming formulas run as real Python rather than a safe expression language: `=__import__('os').name`
2. Once confirmed, read the flag straight out of the process environment: `=__import__('os').environ.get('FLAG')`

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
