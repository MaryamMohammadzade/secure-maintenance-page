# Secure Maintenance Page

A security-focused WordPress plugin that puts your site into **maintenance mode** and shows visitors your own HTML page, or one of four built-in templates (Persian or English, light or dark).

## Features

- Upload a custom HTML maintenance page from the dashboard (**Settings → Maintenance Mode**)
- Four built-in templates: Light and Dark, each in Persian (RTL) and English (LTR)
- If no file is uploaded, Template 1 in the site language is used
- Admin screen in English, with a Persian (fa_IR) translation included
- Preview any template before enabling it
- Logged-in administrators keep seeing the real site; the login page always stays reachable
- Sends `503 Service Unavailable` with a `Retry-After` header, so search engines know the downtime is temporary
- Optionally blocks the REST API and XML-RPC for non-admins while maintenance is on
- Automatic placeholders: `{{site_name}}`, `{{site_description}}`, `{{year}}`

## Security

- Capability check (`manage_options`) and nonce verification on every action
- Upload validation: `.html`/`.htm` extension, real MIME type, 1 MB size limit, valid UTF-8; files containing PHP code are rejected
- The page is stored in the database, never written to disk as a web-accessible file
- Allowlist HTML sanitizer removes scripts, iframes, forms, SVG/MathML, `on*` event handlers, `javascript:` URLs, `<base>` and meta refresh
- Hardened response headers: a strict Content-Security-Policy (no script execution), `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `X-Robots-Tag: noindex`

> Uploaded pages must be plain HTML and CSS. JavaScript is intentionally stripped and blocked.

## Installation

1. Download `secure-maintenance-page.zip` from [Releases](../../releases).
2. In WordPress go to **Plugins → Add New → Upload Plugin**, upload the zip and activate it.
3. Open **Settings → Maintenance Mode**, choose a template or upload your HTML file, tick **Enable** and save.

After enabling, clear any page cache (caching plugins, CDN). Test in a private window, since logged-in admins bypass the maintenance page.

## Requirements

- WordPress 5.8 or later
- PHP 7.4 or later with the DOM extension

## Hooks

| Filter | Default | Purpose |
|---|---|---|
| `smp_bypass_capability` | `manage_options` | Capability that bypasses maintenance mode |
| `smp_max_upload_bytes` | `1048576` | Maximum upload size in bytes |

## License

GPL-2.0-or-later
