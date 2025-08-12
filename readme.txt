=== IP Login Restrictor ===
Contributors: gti-inc
Tags: security, IP, login, admin, restrict
Requires at least: 5.0
Tested up to: 6.5
Stable tag: 1.1.6
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict login and admin access by IP address (including CIDR). Allows emergency IP via wp-config.php.  
Now supports enable/disable switch, admin bar status, and HTML custom access-denied messages.

== License ==
This plugin is licensed under the GNU General Public License v2 or later.

== Third-Party Libraries ==
This plugin uses the following third-party library:

* Plugin Update Checker (MIT License)
  https://github.com/YahnisElsts/plugin-update-checker

== Description ==

This plugin allows you to restrict access to the WordPress login page and admin area by IP address or CIDR range.

日本語の説明はこちら → readme-ja.txt を参照してください。

**Features:**

- Block all access to `wp-login.php` and `wp-admin/` except from allowed IP addresses
- Supports CIDR notation (e.g. `192.168.1.0/24`)
- **Enable/disable restriction via admin settings (radio button)**
- **Admin bar shows restriction status (green=enabled, gray=disabled) and current IP**
- Add emergency IP address via `wp-config.php`:
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`
- Bypass IP restriction entirely with:
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`
- Optional IP whitelist settings screen in admin
- **Custom "Access Denied" message supports HTML and is displayed inside your theme's header/footer**
- **Supports tokens in message: `{ip}`, `{datetime}`, `{site_name}`**
- Add current IP with one click in settings
- Logs in users normally if IP is allowed
- Does not restrict AJAX or admin-post endpoints
- LOLIPOP! Fixed IP service link included

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/ip-login-restrictor` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress (initial status is Disabled).
3. Go to `IP Login Restrictor` in the admin menu to configure allowed IPs and settings.

== Frequently Asked Questions ==

= How do I allow an emergency IP? =
Add the following to your `wp-config.php`:

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= How do I disable all IP restrictions temporarily? =
Add the following line to your `wp-config.php`:

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

= Can I use HTML in the access denied message? =
Yes. The message is displayed inside your theme's header/footer, and supports `{ip}`, `{datetime}`, and `{site_name}` placeholders.

== Screenshots ==

1. IP restriction settings page with status toggle, whitelist, and custom message.
2. Admin bar showing restriction status and current IP.

== Changelog ==

= 1.1.6 =
* Added enable/disable toggle with radio buttons
* Added admin bar status display with green/gray color
* Added current IP display in admin bar when enabled
* Access denied message now supports HTML (within theme's header/footer)
* Added `{ip}`, `{datetime}`, `{site_name}` tokens for message customization

= 1.1.1 =
* Added `REMOVE_WP_LOGIN_IP_ADDRESS` override support
* Added LOLIPOP! Fixed IP service link
* Added current IP auto-fill and emergency access helper
* Minor UI improvements

= 1.0 =
* Initial release
