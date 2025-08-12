=== IP Login Restrictor ===
Contributors: gti-inc
Tags: security, IP, login, admin, restrict
Requires at least: 5.0
Tested up to: 6.8.2
Stable tag: 1.1.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict access to the WordPress login page and admin area by specific IP addresses or CIDR ranges. Supports emergency IP configuration via wp-config.php.

== Description ==

This plugin allows you to restrict access to the WordPress login page (`wp-login.php`) and admin area (`wp-admin/`) to specific IP addresses or CIDR ranges.

日本語の説明はこちら → readme-ja.txt を参照してください。

**Features:**

- Restrict `wp-login.php` and `wp-admin/` access to allowed IP addresses only
- Supports CIDR notation (e.g., `192.168.1.0/24`)
- Toggle restriction **ON/OFF** from the admin menu (radio button)
- Allow an emergency IP via `wp-config.php`:
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`
- Disable all restrictions temporarily:
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`
- Edit allowed IP list from the admin page
- HTML-based access denied message, independent of theme header/footer
- Available tokens in the message: `{ip}`, `{datetime}`, `{site_name}`
- Add your current IP with one click
- Displays status and current IP in the admin bar
- Supports auto-update notifications via GitHub

**Note:** `admin-ajax.php` and `admin-post.php` are not affected.

== Installation ==

1. Upload the plugin to `/wp-content/plugins/ip-login-restrictor` or install it via the WordPress admin panel.
2. Activate the plugin from the "Plugins" menu.
3. Configure the allowed IP addresses in the "IP Login Restrictor" menu.

== Frequently Asked Questions ==

= How do I allow an emergency IP? =  
Add the following line to `wp-config.php`:

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= How do I disable all IP restrictions temporarily? =  
Add the following line to `wp-config.php`:

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

== Screenshots ==

1. Allowed IP settings screen (with emergency IP description)
2. Access denied message customization (HTML)

== Changelog ==

= 1.1.6 =
* Added ON/OFF toggle from settings page
* Access denied message can now be customized with HTML (theme-independent)
* Added `{ip}`, `{datetime}`, `{site_name}` tokens to message body
* Added translation for default message

= 1.1.1 =
* Added `REMOVE_WP_LOGIN_IP_ADDRESS` override
* Added LOLIPOP! fixed IP service link
* Added current IP auto-fill and emergency access info
* UI improvements and minor fixes

= 1.0 =
* Initial release

== License ==
This plugin is licensed under the GNU General Public License v2 or later.

== Third-party Libraries ==
* Plugin Update Checker (MIT License)  
  https://github.com/YahnisElsts/plugin-update-checker
