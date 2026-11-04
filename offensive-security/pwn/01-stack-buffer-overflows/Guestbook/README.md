# Guestbook

**Category:** pwn / stack buffer overflow · **Course:** Offensive Security (PoliTo)

## Challenge

A tiny "guestbook" service reads a name into a 64-byte stack buffer, then returns. A `win()` function that spawns `/bin/sh` exists in the binary but is never called.

## Vulnerability

`vuln()` calls `read(STDIN_FILENO, buf, 256)` into `char buf[64]` — the read length (256) is far larger than the buffer (64), so the saved return address on the stack can be overwritten directly. There is no stack canary on this binary, so a straight-line overflow is enough.

## Exploitation

1. Cyclic-pattern analysis gives the offset from the start of `buf` to the saved return address: **72 bytes**.
2. Overwrite the return address with a single `ret` gadget first, purely to realign the stack pointer to a 16-byte boundary before the real call (`movaps`-based stack corruption otherwise crashes glibc on the way into `system()`).
3. Follow it with the address of `win()` so execution jumps straight there after the `ret` gadget fires.

As in `solve.py`:

```python
offset = 72
ret    = 0x000000000040101a   # bare `ret` gadget, for 16-byte stack alignment

payload = flat(
    b"A" * offset,
    p64(ret),
    p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `guestbook` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
