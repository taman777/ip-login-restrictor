<?php

/**
 * Plugin Name: IP Login Restrictor
 * Plugin URI: https://github.com/taman777/ip-login-restrictor
 * Description: 指定された IP アドレス・CIDR だけが WordPress にログイン・管理画面にアクセスできます。wp-config.php に定義すれば緊急避難IPも許可されます。
 * Version: 1.1.3
 * Author: T.Satoh @ GTI Inc.
 * Text Domain: ip-login-restrictor
 * Domain Path: /languages
 */


require __DIR__ . '/vendor/autoload.php';

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

$updateChecker = PucFactory::buildUpdateChecker(
    'https://github.com/taman777/ip-login-restrictor',
    __FILE__, // ファイルパス
    'ip-login-restrictor' // ディレクトリ名
);

// タグ or ブランチの指定
$updateChecker->setBranch('main');

// Load textdomain
add_action('plugins_loaded', function () {
    load_plugin_textdomain('ip-login-restrictor', false, dirname(plugin_basename(__FILE__)) . '/languages');
});

add_action('init', 'ip_login_restrictor_init');
function ip_login_restrictor_init()
{
    if (defined('REMOVE_WP_LOGIN_IP_ADDRESS') && REMOVE_WP_LOGIN_IP_ADDRESS === true) {
        return;
    }

    if (!(is_admin() || is_login_page()) || is_ajax_or_post()) {
        return; // フロント or Ajax/post は除外
    }

    $allowed_ips = get_option('ip_login_restrictor_ips', []);
    if (defined('WP_LOGIN_IP_ADDRESS')) {
        $allowed_ips[] = WP_LOGIN_IP_ADDRESS;
    }

    $remote_ip = get_client_ip();
    if (!ip_in_allowed_list($remote_ip, $allowed_ips)) {
        $message = get_option('ip_login_restrictor_message', __('Access denied. Your IP address is not allowed.', 'ip-login-restrictor'));
        header('HTTP/1.1 403 Forbidden');
        header('Content-Type: text/plain; charset=UTF-8');
        echo esc_html($message);
        exit;
    }
}

add_action('plugins_loaded', function () {
    load_plugin_textdomain('ip-login-restrictor', false, dirname(plugin_basename(__FILE__)) . '/languages');
});


function is_login_page()
{
    return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php']);
}

function is_ajax_or_post()
{
    $script = $_SERVER['SCRIPT_NAME'] ?? '';
    return strpos($script, 'admin-ajax.php') !== false || strpos($script, 'admin-post.php') !== false;
}

function get_client_ip()
{
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
        return $_SERVER['HTTP_CLIENT_IP'];
    }
    if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
        return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
    }
    return $_SERVER['REMOTE_ADDR'];
}

function ip_in_allowed_list($ip, $allowed_list)
{
    foreach ($allowed_list as $allowed_ip) {
        $allowed_ip = trim($allowed_ip);
        if (strpos($allowed_ip, '/') !== false) {
            if (cidr_match($ip, $allowed_ip)) return true;
        } else {
            if ($ip === $allowed_ip) return true;
        }
    }
    return false;
}

function cidr_match($ip, $cidr)
{
    list($subnet, $mask) = explode('/', $cidr);
    $ip_dec = ip2long($ip);
    $subnet_dec = ip2long($subnet);
    $mask_dec = ~((1 << (32 - $mask)) - 1);
    return ($ip_dec & $mask_dec) === ($subnet_dec & $mask_dec);
}

// 管理画面で設定追加
add_action('admin_menu', 'add_admin_menu_ip_login_restrictor');
function add_admin_menu_ip_login_restrictor()
{
    // 管理画面メニュー名
    add_menu_page(
        __('IP Login Restrictor', 'ip-login-restrictor'),
        __('IP Login Restrictor', 'ip-login-restrictor'),
        'manage_options',
        'ip-login-restrictor',
        'ip_login_restrictor_settings_page',
        'dashicons-shield',
        80
    );
}

function ip_login_restrictor_settings_page()
{
    if (!current_user_can('manage_options')) return;

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        check_admin_referer('ip_login_restrictor_save');

        if (isset($_POST['ip_login_restrictor_ips'])) {
            $ips = array_filter(array_map('trim', explode("
", sanitize_textarea_field($_POST['ip_login_restrictor_ips']))));
            update_option('ip_login_restrictor_ips', $ips);
        }

        if (isset($_POST['ip_login_restrictor_message'])) {
            $msg = sanitize_text_field($_POST['ip_login_restrictor_message']);
            update_option('ip_login_restrictor_message', $msg);
        }

        echo '<div class="updated"><p>' . esc_html__('Settings saved.', 'ip-login-restrictor') . '</p></div>';
    }

    $ips = implode("
", get_option('ip_login_restrictor_ips', []));
    $message = get_option('ip_login_restrictor_message', __('Access denied. Your IP address is not allowed.', 'ip-login-restrictor'));
    $current_ip = esc_html($_SERVER['REMOTE_ADDR']);
?>
    <div class="wrap">
        <h1><?php _e('IP Login Restrictor Settings', 'ip-login-restrictor'); ?></h1>
        <form method="post">
            <?php wp_nonce_field('ip_login_restrictor_save'); ?>
            <p><?php _e('Allowed IP addresses or CIDR ranges (one per line):', 'ip-login-restrictor'); ?></p>
            <textarea name="ip_login_restrictor_ips" rows="10" cols="60"><?php echo esc_textarea($ips); ?></textarea><br>

            <p>
                <button type="button" class="button" onclick="addCurrentIP()"><?php _e('Add current IP address', 'ip-login-restrictor'); ?></button>
                <span style="margin-left:10px;"><?php _e('Your IP:', 'ip-login-restrictor'); ?> <?php echo $current_ip; ?></span>
            </p>

            <h2><?php _e('Access Denied Message', 'ip-login-restrictor'); ?></h2>
            <input type="text" name="ip_login_restrictor_message" value="<?php echo esc_attr($message); ?>" size="60">
            <p class="description"><?php _e('This message is shown when access is denied due to IP restriction.', 'ip-login-restrictor'); ?></p>

            <p class="submit"><input type="submit" class="button-primary" value="<?php esc_attr_e('Save Changes', 'ip-login-restrictor'); ?>"></p>
        </form>
        <p><strong><?php _e('Emergency IP:', 'ip-login-restrictor'); ?></strong> <?php _e('You can add', 'ip-login-restrictor'); ?> <code>define('WP_LOGIN_IP_ADDRESS', 'xxx.xxx.xxx.xxx');</code> <?php _e('to wp-config.php to allow access.', 'ip-login-restrictor'); ?></p>
        <p><strong><?php _e('Disable restriction:', 'ip-login-restrictor'); ?></strong> <?php _e('Add', 'ip-login-restrictor'); ?> <code>define('REMOVE_WP_LOGIN_IP_ADDRESS', true);</code> <?php _e('to disable all IP restrictions.', 'ip-login-restrictor'); ?></p>

        <!-- LOLIPOP!固定IPアクセスのためのリンク -->
        <p>
            安心して管理画面にアクセスするために固定IPが必要ですか？<br>
            <a href="https://vpn.lolipop.jp/" target="_blank" rel="noopener noreferrer">
                LOLIPOP!固定IPアクセス サービスをご覧ください
            </a>
        </p>
    </div>
    <script>
        function addCurrentIP() {
            const ip = "<?php echo esc_js($_SERVER['REMOTE_ADDR']); ?>";
            const textarea = document.querySelector('textarea[name="ip_login_restrictor_ips"]');
            const lines = textarea.value.split(/\r?\n/).map(l => l.trim());
            if (!lines.includes(ip)) {
                lines.push(ip);
                textarea.value = lines.filter(Boolean).join("\n");
            } else {
                alert("<?php echo esc_js(__('This IP address is already added.', 'ip-login-restrictor')); ?>");
            }
        }
    </script>
<?php
}

// アンインストール処理
register_uninstall_hook(
    __FILE__,
    'ip_login_restrictor_uninstall'
);
function ip_login_restrictor_uninstall()
{
    delete_option('ip_login_restrictor_ips');
    delete_option('ip_login_restrictor_message');
}
