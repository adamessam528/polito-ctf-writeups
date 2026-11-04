# QRDrop

**Category:** web / command injection via shell quote breakout (`qrencode`) · **Course:** Offensive Security (PoliTo)

## Challenge

A QR-code generator: `POST /generate` takes a `url` field and shells out to the `qrencode` CLI to render it as a PNG.

## Vulnerability

```js
const cmd = `qrencode -t PNG -o ${outputPath} -s 8 -m 2 '${url}'`;
exec(cmd, { timeout: 5000 }, ...);
```

`url` is interpolated directly into a shell command string, wrapped in single quotes as if that were sufficient sanitisation. Since the value isn't checked for embedded single quotes, an attacker can close that quoted string early and append new `qrencode` flags — this is argument injection riding on a shell quote breakout, not just plain metacharacter injection.

## Exploitation

`qrencode` has a `--read-from=FILE` flag that reads the data to encode from a file instead of from the command line argument. Breaking out of the single-quoted `url` argument to inject that flag makes `qrencode` read and encode the contents of `/flag.txt` instead of the intended URL — the flag then comes back embedded in the generated QR image, decodable by scanning it:

```
--read-from=/flag.txt
```

appended after closing the single-quoted url argument, e.g. `' --read-from=/flag.txt '`

## Files

- `app.js` — challenge server source (Express), showing the vulnerable `exec()` call

## Flag

`offsec{qr_dr0p_qu0t3_br34k_...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
