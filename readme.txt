=== IP Login Restrictor ===
Contributors: gti-inc
Tags: security, IP, login, admin, restrict
Requires at least: 5.0
Tested up to: 6.5
Stable tag: 1.1.3
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict login and admin access by IP address (including CIDR). Allows emergency IP via wp-config.php.

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
- Add emergency IP address via `wp-config.php`:
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`
- Bypass IP restriction entirely with:
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`
- Optional IP whitelist settings screen in admin
- Logs in users normally if IP is allowed
- Does not restrict AJAX or admin-post endpoints

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/ip-login-restrictor` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to `Settings > IP Login Restrictor` to configure allowed IPs.

== Frequently Asked Questions ==

= How do I allow an emergency IP? =
Add the following to your `wp-config.php`:

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= How do I disable all IP restrictions temporarily? =
Add the following line to your `wp-config.php`:

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

== Screenshots ==

1. IP restriction settings page with optional emergency IP.
2. Admin notice and code snippet for emergency access.

== Changelog ==

= 1.1.1 =
* Added `REMOVE_WP_LOGIN_IP_ADDRESS` override support
* Added LOLIPOP! Fixed IP service link
* Added current IP auto-fill and emergency access helper
* Minor UI improvements

= 1.0 =
* Initial release
