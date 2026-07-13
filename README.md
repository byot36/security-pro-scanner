# My Security Pro Scanner

WordPress security scanner with backdoor detection, HTTP security header auditing, exposed port checks, SQL injection risk analysis, and one-click automatic fixes — all running from your own WordPress admin, with no external accounts or API keys required.

## Features

- **Backdoor & malware detection** — scans core files and installed plugins for suspicious code patterns (`eval`, `base64_decode`, `assert`).
- **File permission audits** — flags risky permissions on `wp-config.php`.
- **REST API exposure check** — warns if the `/wp-json/wp/v2/users` endpoint leaks too many usernames.
- **HTTP security headers** — detects missing `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, `Referrer-Policy`, and `Strict-Transport-Security`.
- **Exposed port detection** — checks whether MySQL, PostgreSQL, Redis, or FTP ports are reachable on your own server.
- **SQL injection risk (static analysis)** — scans installed plugin/theme PHP files for unprepared `$wpdb` queries built from request input.
- **SQLi/XSS self-test (dynamic, optional)** — sends a handful of test payloads exclusively to your own site, never to an external target.
- **One-click automatic fix** — writes missing security headers directly into `.htaccess` via WordPress's native `insert_with_markers()`, then re-verifies with a live request to confirm the fix actually worked.
- **Real-time state, not a growing log** — the dashboard shows only currently open issues; anything confirmed fixed disappears automatically, with a separate "Fix History" list for the audit trail.

## Installation

1. Download this repository as a ZIP (**Code → Download ZIP**), or clone it.
2. Upload the `my-security-scanner-pro` folder to `wp-content/plugins/`.
3. Activate **My Security Pro Scanner** from the WordPress Plugins screen.
4. Go to **Security Pro → Manual Scan** to run your first scan.

## Project Structure

```
my-security-scanner-pro/
├── my-security-scanner-pro.php   # Bootstrap: activation, hooks, wiring
├── includes/
│   ├── class-msp-scanner.php     # Detection logic (headers, ports, SQLi, backdoors)
│   ├── class-msp-ajax.php        # AJAX handlers for manual scans and fixes
│   └── class-msp-state.php       # Tracks current open issues + fix history
├── admin/
│   └── class-msp-admin.php       # Admin menu and page rendering
└── assets/
    ├── css/admin.css
    └── js/admin.js
```

## Important Notes

- This plugin only scans and acts on **your own site**. There is no feature to target external URLs — by design, to prevent it from ever being usable as a scanning tool against third-party sites.
- The automatic header fix only writes rules WordPress core already supports (`insert_with_markers`) and re-checks live headers before claiming success — it never assumes a fix worked without verification.
- Not affiliated with or endorsed by any third-party vulnerability database.

## License

GPLv2 or later.
