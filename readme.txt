=== IP Login Restrictor ===
Contributors: gti-inc, taman777
Tags: security, ip, restriction, login, admin, maintenance, staging
Requires at least: 5.0
Tested up to: 6.5
Stable tag: 1.2.1
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

Restrict login, admin, and frontend access by IP address. Includes Rescue URL and emergency override. Ideal for staging sites.

== Description ==

This plugin provides a robust way to restrict access to your WordPress site based on IP addresses.
It is perfect for **securing your admin area** or **privately sharing a staging site** during development.

**Key Features:**

*   **Dual Whitelists:** Configure separate IP lists for "Admin/Login" and "Frontend Only".
    *   **Admin/Login:** Secures `wp-admin` and `wp-login.php`.
    *   **Frontend:** Secures public pages (perfect for "Maintenance Mode" or private beta).
*   **Rescue URL (Emergency Access):** Generate a secret URL (e.g., `/?iplr_rescue=mysecretkey`) to automatically add your new IP to the whitelist if you get locked out.
*   **Ideal for Staging:** Easily restrict access to your development site so only clients or team members can see it.
*   **HTML Custom Message:** Customize the "Access Denied" screen with HTML. It automatically inherits your theme's header and footer for a seamless look.
*   **CIDR Support:** Works with individual IPs (e.g., `192.168.1.1`) and ranges (e.g., `192.168.1.0/24`).
*   **Admin Bar Status:** Quickly see if restriction is Enabled/Disabled and check your current IP from the admin bar.
*   **Emergency Override:** Supports `wp-config.php` constants for emergency access.

**Use Cases:**

*   **Security:** Block all brute-force attacks by allowing login only from your office or home.
*   **Staging/Dev Sites:** Limit visibility of a work-in-progress site to specific stakeholders without dealing with password management.
*   **Intranet:** Use WordPress as an internal tool accessible only from your VPN or corporate network.

== Installation ==

1. Upload the plugin files to the `/wp-content/plugins/ip-login-restrictor` directory, or install the plugin through the WordPress plugins screen directly.
2. Activate the plugin through the 'Plugins' screen in WordPress.
3. Go to **Settings > IP Login Restrictor** to configure.
4. Add your IP address to the whitelist and set the status to **Enabled**.
5. (Recommended) Set a **Rescue Key** and bookmark the generated URL.

== Frequently Asked Questions ==

= I locked myself out! What do I do? =
If you set up a **Rescue URL**, access it now to whitelist your new IP.
If not, you can manually add your IP via FTP. Add this to your `wp-config.php`:
`define('WP_LOGIN_IP_ADDRESS', 'YOUR.IP.ADDRESS');`

= How do I disable the plugin via FTP? =
Add this line to `wp-config.php` to bypass all restrictions:
`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

= Can I restrict the public site but allow everyone to login? =
No. If you restrict the Frontend, you usually restrict Admin/Login too. The "Admin IP List" allows access to EVERYTHING (Admin + Frontend). The "Frontend IP List" only allows access to the Frontend.

== Screenshots ==

1. Settings Page: Manage IP lists, Rescue URL, and Custom Message.
2. Rescue URL settings.
3. Access Denied screen (inherits theme design).

== Changelog ==

= 1.2.1 =
*   **UX:** Frontend IP list section now auto-hides when "Allow All" is selected.

= 1.2.0 =
*   **New:** Rescue URL feature! Generate a secret link to auto-whitelist your new IP.
*   **New:** Frontend Restriction! Optionally restrict access to public pages (great for staging sites).
*   **New:** Separate whitelist for "Frontend Only" access.
*   **Update:** Admin bar now shows if Frontend restriction is active.
*   **Update:** Improved "Access Denied" message styling options.
*   **Fix:** Resolved localization issues (Japanese support improved).

= 1.1.6 =
*   Added enable/disable toggle
*   Added admin bar status
*   Added HTML message support

= 1.0.0 =
*   Initial release
