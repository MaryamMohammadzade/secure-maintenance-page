=== Secure Maintenance Page ===
Requires at least: 5.8
Tested up to: 6.8
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Security-focused maintenance mode with your own uploaded HTML page or one of four built-in templates.

== Description ==

* Upload a custom HTML maintenance page from the dashboard.
* Four built-in templates: Light and Dark, in Persian and English.
* Admin screen in English with a Persian translation.
* Administrators bypass the maintenance page; wp-login.php stays reachable.
* Sends 503 with Retry-After, a strict Content-Security-Policy and noindex headers.
* Uploaded HTML is validated and sanitized; JavaScript is removed.
* Placeholders: {{site_name}}, {{site_description}}, {{year}}.

== Installation ==

1. Plugins > Add New > Upload Plugin, choose the zip and activate.
2. Settings > Maintenance Mode: pick a template or upload an HTML file, enable and save.
3. Clear any page cache or CDN cache.

== Changelog ==

= 1.1.0 =
* Added English versions of both templates.
* Admin screen is now English with a bundled Persian translation.

= 1.0.0 =
* Initial release.
