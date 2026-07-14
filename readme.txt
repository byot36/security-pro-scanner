=== My Security Pro Scanner ===
Contributors: byot, alkesh7
Tags: security, malware, firewall, vulnerability, backdoor
Requires at least: 6.5
Tested up to: 7.0
Requires PHP: 7.4
Stable tag: 1.1.0
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Scans your WordPress site for backdoors, insecure file permissions, missing security headers, exposed ports, and SQL injection risk.

== Description ==

My Security Pro Scanner is a self-contained security auditor for WordPress. It runs entirely from your own admin dashboard — no external accounts, API keys, or third-party services required — and checks your site for the issues that most basic scanners miss.

**What it checks:**

* **Backdoor & malware detection** — scans WordPress core files and installed plugins for suspicious code patterns (`eval`, `base64_decode`, `assert`).
* **File permission audits** — flags risky file permissions on `wp-config.php`.
* **REST API exposure check** — warns if the `/wp-json/wp/v2/users` endpoint is leaking too many usernames.
* **HTTP security headers** — detects missing `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and `Strict-Transport-Security`.
* **Exposed port detection** — checks whether MySQL, PostgreSQL, Redis, or FTP ports are reachable on your own server.
* **SQL injection risk (static analysis)** — scans installed plugin and theme PHP files for unprepared `$wpdb` queries built from request input.
* **SQLi/XSS self-test (dynamic, optional)** — sends a handful of test payloads exclusively to your own site, never to an external target.
* **One-click automatic fix** — writes missing security headers directly into `.htaccess` via WordPress's native `insert_with_markers()`, then re-verifies with a live request to confirm the fix actually worked.
* **Real-time state, not a growing log** — the dashboard shows only currently open issues; anything confirmed fixed disappears automatically, with a separate "Fix History" list for the audit trail.

**Why it's different:** this plugin only ever scans and acts on your own site. There is no feature to target external URLs, by design, so it can never be repurposed as a scanning tool against third-party sites.

= Privacy =

All checks run against your own site (`home_url()`) or your own local filesystem. The plugin makes no calls to any third-party service and does not transmit data off your server.

== Installation ==

1. Upload the `my-security-scanner-pro` folder to `/wp-content/plugins/`, or install it directly from the WordPress Plugins screen.
2. Activate the plugin through the 'Plugins' menu in WordPress.
3. Go to **Security Pro → Manual Scan** to run your first scan.

== Frequently Asked Questions ==

= Does this plugin send my data to an external server? =

No. Every check runs against your own site or your own server's filesystem. Nothing is sent to any third party.

= Will the automatic header fix break my site? =

The fix only writes rules that WordPress core already supports (`insert_with_markers()`) inside a clearly delimited block in `.htaccess`, and it re-checks live HTTP headers afterward to confirm the fix actually took effect, it never assumes success.

= Can I use this to scan someone else's website? =

No. Every scan module targets your own site's `home_url()` or local files only. There is no field to enter an external URL.

== Changelog ==

= 1.1.0 =
* Security: All custom SQL queries now use `$wpdb->prepare()` with the `%i` identifier placeholder.
* Security: Settings form input is unslashed before sanitization; added an explicit capability check alongside the existing nonce check.
* Update: Replaced `json_encode()` calls with `wp_json_encode()` throughout.
* Update: Added `Requires at least`, `Requires PHP`, `License`, and `License URI` headers; corrected the `Text Domain` to match the plugin's folder slug.
* Update: Confirmed compatibility with WordPress 7.0.
* Fix: Loose (`==`) comparisons replaced with strict (`===`) comparisons.
* Fix: Removed unreachable `die()` call after `wp_send_json()`, which already terminates the request.

= 1.0.0 =
* Initial release.

== Upgrade Notice ==

= 1.1.0 =
Security hardening (prepared SQL queries, stricter input sanitization) and confirmed WordPress 7.0 compatibility. Upgrade recommended.
