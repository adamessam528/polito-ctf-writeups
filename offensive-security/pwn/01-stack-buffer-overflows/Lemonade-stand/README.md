# Lemonade Stand

**Category:** pwn / stack variable overwrite · **Course:** Offensive Security (PoliTo)

## Challenge

`vuln()` declares `volatile int target = 0;` right next to `char buffer[64];` and grants a shell if `target == 0x1337` after reading user input — no pointers or return address involved at all.

## Vulnerability

`scanf("%s", buffer)` has no length limit, so input keeps writing past `buffer` into whatever the compiler placed next on the stack — which happens to be `target`. This is a control-flow-free overflow: no ROP, no canary defeat, just landing the right bytes in the right place.

## Exploitation

1. Pad up to the offset separating `buffer` from `target` (the 64-byte buffer plus stack layout and the `volatile` guard, **76 bytes** observed empirically).
2. Write `0x1337` right after the padding. `solve.py` packs it with `p64`; the low 4 bytes land exactly on the 4-byte `target`, and the high bytes fall on an unused slot.

As in `solve.py`:

```python
offset_target = 76
payload = b"A" * offset_target + p64(0x1337)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fno-stack-protector -O0 -g`: no canary)
- `lemonade_stand` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
