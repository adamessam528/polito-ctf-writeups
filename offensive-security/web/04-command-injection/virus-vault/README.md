# VirusVault

**Category:** web / blind command injection (time-based, file upload) · **Course:** Offensive Security (PoliTo)

## Challenge

A file-scanning service accepts an uploaded "specimen" and appears to run it through some kind of command-line scanner, keyed off the uploaded filename. There's no reflected output to read directly — the response looks the same whether the injected command succeeds or fails.

## Vulnerability

Blind command injection: the uploaded file's *name* is passed unsanitised into a shell command (pattern `file|<something>`), but the response body gives no direct feedback. With no output channel and no boolean signal, the exploit uses a **time-based side channel** — injecting `&& sleep N` and measuring response latency confirms whether a guessed condition was true.

## Exploitation

The accompanying `solve.py` automates a character-by-character extraction that matches these steps exactly:

1. The payload is delivered as the **filename** of the multipart `specimen` upload field. The backend splices that name into a shell command, so a leading `file|printenv` pipes the process environment into the next command.
2. Build an oracle over a fixed charset. For each candidate character, grep the environment for the flag prefix recovered so far plus that candidate, and only sleep if the grep matches:

   ```python
   payload = f"file|printenv | grep -F 'FLAG={test_flag}' && sleep 5"
   ```

3. POST it to `/scan` and measure elapsed time. A response slower than ~3 s means the `grep` matched, so the candidate is correct — append it and move to the next position.
4. Repeat until the recovered flag ends with `}`. Extraction starts from the known prefix `offsec{`.

## Files

- `solve.py` — the exact blind/time-based extraction script used (target URL redacted to `https://CHALLENGE-INSTANCE`; no challenge source retained)

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

The script accepts the first candidate whose response crosses the ~3 s threshold (a single `sleep 5` sample). Against a noisy network a more robust version would re-test each timing hit to rule out jitter, but the single-sample approach was enough against this lab instance.
