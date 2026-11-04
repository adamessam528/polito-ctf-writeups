# Enchanted Forest

**Category:** pwn / struct callback overwrite · **Course:** Offensive Security (PoliTo)

## Challenge

`vuln()` builds a local struct holding a 64-byte `incantation` buffer directly followed by a function pointer `cast`, defaulted to a harmless `default_spell`. After reading input it calls `spell.cast()`.

## Vulnerability

Despite the binary's name (this one lives in the "canaries" recap set), the struct's function pointer sits *before* any canary would be checked, and `read(..., 128)` into the 64-byte `incantation` field overflows straight into `cast` — no canary defeat is even required to win.

## Exploitation

1. Pad 64 bytes to fill `incantation` and reach the `cast` field exactly.
2. Overwrite `cast` with the address of `win()`, which `execve`s `/bin/sh`.

As in `solve.py`:

```python
payload = flat(
    b"A" * 64,
    p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `canary_callback` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
