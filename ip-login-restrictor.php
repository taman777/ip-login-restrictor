<?php

/**
 * Plugin Name: IP Login Restrictor
 * Plugin URI: https://github.com/taman777/ip-login-restrictor
 * Description: 指定された IP アドレス・CIDR だけが WordPress にログイン・管理画面にアクセスできます。wp-config.php に定義すれば緊急避難IPも許可されます。
 * Version: 1.1.7
 * Author: T.Satoh @ GTI Inc.
 * Text Domain: ip-login-restrictor
 * Domain Path: /languages
 */

if (!defined('ABSPATH')) exit;

// Composer autoload（存在チェック）
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

use YahnisElsts\PluginUpdateChecker\v5\PucFactory;

class IP_Login_Restrictor
{

    const OPTION_IPS      = 'ip_login_restrictor_ips';
    const OPTION_ENABLED  = 'ip_login_restrictor_enabled'; // '1' or '0'
    const OPTION_MSG_BODY = 'ip_login_restrictor_message_body_html'; // 本文のみHTML

    /** @var string 管理メニューのフック名（load-フックでPOST処理用） */
    private $menu_hook = '';

    public function __construct()
    {
        add_action('plugins_loaded', [$this, 'load_textdomain']);
        add_action('init',            [$this, 'check_access']);
        add_action('admin_menu',      [$this, 'add_admin_menu']);
        add_action('admin_bar_menu',  [$this, 'add_admin_bar_status'], 100);

        // 管理バー色付け（有効=緑 / 無効=グレー）
        add_action('admin_head',      [$this, 'output_adminbar_css']);
        add_action('wp_head',         [$this, 'output_adminbar_css']);

        register_activation_hook(__FILE__, ['IP_Login_Restrictor', 'activate']);
        register_uninstall_hook(__FILE__,  ['IP_Login_Restrictor', 'uninstall']);

        $this->init_update_checker();
    }

    /** 言語ロード */
    public function load_textdomain()
    {
        load_plugin_textdomain('ip-login-restrictor', false, dirname(plugin_basename(__FILE__)) . '/languages');
    }

    /** PUC 初期化 */
    private function init_update_checker()
    {
        if (class_exists(PucFactory::class)) {
            $updateChecker = PucFactory::buildUpdateChecker(
                'https://github.com/taman777/ip-login-restrictor',
                __FILE__,
                'ip-login-restrictor'
            );
            $updateChecker->setBranch('main');
            // Private リポの場合のみ：
            // if (defined('GITHUB_TOKEN') && GITHUB_TOKEN) { $updateChecker->setAuthentication(GITHUB_TOKEN); }
        }
    }

    /** 翻訳対応のデフォルト本文（HTML）を返す */
    private function get_default_body_html_translated()
    {
        // トークンはこのまま保持（後で置換）
        $tpl = __(
            '<h1>Access Denied</h1><p class="description">This IP address ({ip}) is not allowed to access the admin/login of {site_name}.<br><small>As of {datetime}</small></p>',
            'ip-login-restrictor'
        );
        return $tpl;
    }

    /** 有効化時: いきなりONにしない。本文HTMLのデフォルトも翻訳で用意 */
    public static function activate()
    {
        if (get_option(self::OPTION_ENABLED, null) === null) {
            add_option(self::OPTION_ENABLED, '0');
        }
        if (get_option(self::OPTION_IPS, null) === null) {
            add_option(self::OPTION_IPS, []);
        }
        if (get_option(self::OPTION_MSG_BODY, null) === null) {
            // インスタンスを作って翻訳済みテンプレをセット
            add_option(self::OPTION_MSG_BODY, (new self)->get_default_body_html_translated());
        }
    }

    /** アンインストール時: 設定削除 */
    public static function uninstall()
    {
        delete_option(self::OPTION_IPS);
        delete_option(self::OPTION_ENABLED);
        delete_option(self::OPTION_MSG_BODY);
    }

    /** 現在有効か */
    private function is_enabled()
    {
        return get_option(self::OPTION_ENABLED, '0') === '1';
    }

    /** アクセスチェック本体（常にプレーンHTMLで安全に返す） */
    public function check_access()
    {
        if (!$this->is_enabled()) return;
        if (defined('REMOVE_WP_LOGIN_IP_ADDRESS') && REMOVE_WP_LOGIN_IP_ADDRESS === true) return;

        // フロントや Ajax/post は除外
        if (!(is_admin() || $this->is_login_page()) || $this->is_ajax_or_post()) return;

        $allowed_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
            $allowed_ips[] = WP_LOGIN_IP_ADDRESS;
        }

        $remote_ip = $this->get_client_ip();
        if (!$this->ip_in_allowed_list($remote_ip, $allowed_ips)) {
            // 403 + HTML
            status_header(403);
            nocache_headers();
            header('Content-Type: text/html; charset=UTF-8');

            // 本文（未設定や空なら翻訳済みデフォルトで補填）
            $body_html = get_option(self::OPTION_MSG_BODY, '');
            if ($body_html === '') {
                $body_html = $this->get_default_body_html_translated();
            }
            $body_html = wp_kses_post($body_html);

            // 置換トークン
            $replacements = [
                '{ip}'        => esc_html($remote_ip),
                '{datetime}'  => esc_html(date_i18n('Y-m-d H:i:s')),
                '{site_name}' => esc_html(get_bloginfo('name')),
            ];
            $body_html = strtr($body_html, $replacements);

            // プレーンHTMLで返す（テーマ非依存）
            echo '<!doctype html><html lang="' . esc_attr(get_bloginfo('language')) . '"><head><meta charset="utf-8"><title>' . esc_html(__('Access Denied', 'ip-login-restrictor')) . '</title>';
            echo '<meta name="viewport" content="width=device-width,initial-scale=1">';
            echo '<style>body{font-family:system-ui,-apple-system,Segoe UI,Roboto,Helvetica,Arial;line-height:1.6;background:#f8f9fa;color:#212529;display:flex;align-items:center;justify-content:center;height:100vh;margin:0}.box{max-width:720px;background:#fff;border-radius:12px;box-shadow:0 6px 24px rgba(0,0,0,.08);padding:28px}</style>';
            echo '</head><body><div class="box">' . $body_html . '</div></body></html>';

            exit;
        }
    }

    private function is_login_page()
    {
        return in_array($GLOBALS['pagenow'], ['wp-login.php', 'wp-register.php'], true);
    }

    private function is_ajax_or_post()
    {
        $script = $_SERVER['SCRIPT_NAME'] ?? '';
        return (strpos($script, 'admin-ajax.php') !== false) || (strpos($script, 'admin-post.php') !== false);
    }

    private function get_client_ip()
    {
        if (!empty($_SERVER['HTTP_CLIENT_IP']))       return $_SERVER['HTTP_CLIENT_IP'];
        if (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) return explode(',', $_SERVER['HTTP_X_FORWARDED_FOR'])[0];
        return $_SERVER['REMOTE_ADDR'] ?? '';
    }

    private function ip_in_allowed_list($ip, $allowed_list)
    {
        foreach ((array)$allowed_list as $allowed_ip) {
            $allowed_ip = trim((string)$allowed_ip);
            if ($allowed_ip === '') continue;
            if (strpos($allowed_ip, '/') !== false) {
                if ($this->cidr_match($ip, $allowed_ip)) return true;
            } else {
                if ($ip === $allowed_ip) return true;
            }
        }
        return false;
    }

    private function cidr_match($ip, $cidr)
    {
        list($subnet, $mask) = explode('/', $cidr);
        $ip_dec     = ip2long($ip);
        $subnet_dec = ip2long($subnet);
        if ($ip_dec === false || $subnet_dec === false) return false;
        $mask = (int)$mask;
        $mask_dec = ~((1 << (32 - $mask)) - 1);
        return ($ip_dec & $mask_dec) === ($subnet_dec & $mask_dec);
    }

    /** 管理メニュー追加（load-フックでPOST処理→リダイレクト） */
    public function add_admin_menu()
    {
        $this->menu_hook = add_menu_page(
            __('IP Login Restrictor', 'ip-login-restrictor'),
            __('IP Login Restrictor', 'ip-login-restrictor'),
            'manage_options',
            'ip-login-restrictor',
            [$this, 'settings_page'],
            'dashicons-shield',
            80
        );
        add_action("load-{$this->menu_hook}", [$this, 'handle_settings_post']);
    }

    /** POST保存＋リダイレクト（描画前に実行） */
    public function handle_settings_post()
    {
        if ($_SERVER['REQUEST_METHOD'] !== 'POST') return;
        if (!current_user_can('manage_options')) return;

        check_admin_referer('ip_login_restrictor_save');

        // 有効/無効
        if (isset($_POST['ip_login_restrictor_enabled'])) {
            $enabled = ($_POST['ip_login_restrictor_enabled'] === '1') ? '1' : '0';
            update_option(self::OPTION_ENABLED, $enabled);
        }

        // 許可IP
        if (isset($_POST['ip_login_restrictor_ips'])) {
            $lines = preg_split("/\r\n|\r|\n/", (string) $_POST['ip_login_restrictor_ips']);
            $ips   = array_filter(array_map('trim', array_map('sanitize_text_field', $lines)));
            update_option(self::OPTION_IPS, $ips);
        }

        // 本文HTML（安全なHTMLに限定）
        if (isset($_POST['ip_login_restrictor_message_body_html'])) {
            update_option(self::OPTION_MSG_BODY, wp_kses_post($_POST['ip_login_restrictor_message_body_html']));
        }

        // 「デフォルトに戻す」ボタン
        if (isset($_POST['iplr_restore_default_body']) && $_POST['iplr_restore_default_body'] === '1') {
            update_option(self::OPTION_MSG_BODY, $this->get_default_body_html_translated());
        }

        // 空なら翻訳済みデフォルトで補填
        if (get_option(self::OPTION_MSG_BODY, '') === '') {
            update_option(self::OPTION_MSG_BODY, $this->get_default_body_html_translated());
        }
        // 保存後に安全にリダイレクト（管理バーも最新状態で描画）
        wp_safe_redirect(
            add_query_arg(
                ['page' => 'ip-login-restrictor', 'settings-updated' => 'true'],
                admin_url('admin.php')
            )
        );
        exit;
    }

    /** 設定ページ（描画のみ。本文はtextareaでHTML可） */
    public function settings_page()
    {
        if (!current_user_can('manage_options')) return;

        if (isset($_GET['settings-updated']) && $_GET['settings-updated'] === 'true') {
            echo '<div class="updated"><p>' . esc_html__('Settings saved.', 'ip-login-restrictor') . '</p></div>';
        }

        $enabled    = $this->is_enabled();
        $ips        = implode("\n", get_option(self::OPTION_IPS, []));
        $msg_body   = (string) get_option(self::OPTION_MSG_BODY, '');
        $current_ip = esc_html($this->get_client_ip());
?>
        <div class="wrap">
            <h1><?php _e('IP Login Restrictor Settings', 'ip-login-restrictor'); ?></h1>
            <form method="post">
                <?php wp_nonce_field('ip_login_restrictor_save'); ?>

                <h2><?php _e('Status', 'ip-login-restrictor'); ?></h2>
                <label style="display:inline-block;margin-right:16px;">
                    <input type="radio" name="ip_login_restrictor_enabled" value="1" <?php checked($enabled, true); ?>>
                    <span style="color:#1f8f3a;font-weight:700;"><?php _e('Enabled', 'ip-login-restrictor'); ?></span>
                </label>
                <label style="display:inline-block;">
                    <input type="radio" name="ip_login_restrictor_enabled" value="0" <?php checked($enabled, false); ?>>
                    <span style="color:#6c757d;font-weight:700;"><?php _e('Disabled', 'ip-login-restrictor'); ?></span>
                </label>
                <p class="description">
                    <?php _e('When enabled, admin/login access is restricted by the whitelist below.', 'ip-login-restrictor'); ?>
                </p>
                <hr>

                <p><?php _e('Allowed IP addresses or CIDR ranges (one per line):', 'ip-login-restrictor'); ?></p>
                <textarea name="ip_login_restrictor_ips" rows="10" cols="60"><?php echo esc_textarea($ips); ?></textarea><br>

                <p>
                    <button type="button" class="button" onclick="addCurrentIP()"><?php _e('Add current IP address', 'ip-login-restrictor'); ?></button>
                    <span style="margin-left:10px;"><?php _e('Your IP:', 'ip-login-restrictor'); ?> <?php echo $current_ip; ?></span>
                </p>

                <h2><?php _e('Access Denied Body (HTML)', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('You can use basic HTML. Disallowed tags will be removed for security. Available tokens: {ip}, {datetime}, {site_name}.', 'ip-login-restrictor'); ?>
                </p>
                <textarea name="ip_login_restrictor_message_body_html" rows="10" cols="80"><?php echo esc_textarea($msg_body); ?></textarea>

                <p style="margin-top:8px;">
                    <button type="submit" name="iplr_restore_default_body" value="1" class="button">
                        <?php _e('Restore default message', 'ip-login-restrictor'); ?>
                    </button>
                </p>

                <p class="submit" style="margin-top:18px;">
                    <input type="submit" class="button-primary" value="<?php esc_attr_e('Save Changes', 'ip-login-restrictor'); ?>">
                </p>
            </form>

            <p><strong><?php _e('Emergency IP:', 'ip-login-restrictor'); ?></strong>
                <?php _e('You can add', 'ip-login-restrictor'); ?>
                <code>define('WP_LOGIN_IP_ADDRESS', 'xxx.xxx.xxx.xxx');</code>
                <?php _e('to wp-config.php to allow access.', 'ip-login-restrictor'); ?>
            </p>
            <p><strong><?php _e('Disable restriction:', 'ip-login-restrictor'); ?></strong>
                <?php _e('Add', 'ip-login-restrictor'); ?>
                <code>define('REMOVE_WP_LOGIN_IP_ADDRESS', true);</code>
                <?php _e('to disable all IP restrictions.', 'ip-login-restrictor'); ?>
            </p>

            <!-- 国際化なしの告知 -->
            <p>
                安心して管理画面にアクセスするために固定IPが必要ですか？<br>
                <a href="https://vpn.lolipop.jp/" target="_blank" rel="noopener noreferrer">
                    LOLIPOP!固定IPアクセス サービスをご覧ください
                </a>
            </p>
        </div>
        <script>
            function addCurrentIP() {
                const ip = "<?php echo esc_js($this->get_client_ip()); ?>";
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

    /** 管理バー表示（有効/無効。有効時は現在IPも子項目に表示） */
    public function add_admin_bar_status($wp_admin_bar)
    {
        if (!is_admin_bar_showing()) return;
        if (!current_user_can('manage_options')) return;

        $enabled = $this->is_enabled();
        $status_text  = $enabled ? __('Enabled', 'ip-login-restrictor') : __('Disabled', 'ip-login-restrictor');
        $parent_title = sprintf(__('IP Restrictor: %s', 'ip-login-restrictor'), $status_text);

        $wp_admin_bar->add_node([
            'id'    => 'ip-login-restrictor-status',
            'title' => esc_html($parent_title),
            'href'  => admin_url('admin.php?page=ip-login-restrictor'),
            'meta'  => ['class' => $enabled ? 'iplr-on' : 'iplr-off'],
        ]);

        if ($enabled) {
            $wp_admin_bar->add_node([
                'id'     => 'ip-login-restrictor-ip',
                'parent' => 'ip-login-restrictor-status',
                'title'  => esc_html(sprintf(__('Your IP: %s', 'ip-login-restrictor'), $this->get_client_ip())),
                'href'   => false,
            ]);
        }
    }

    /** 管理バーの色付け（Enabled=緑 / Disabled=グレー） */
    public function output_adminbar_css()
    {
        if (!is_admin_bar_showing()) return;
        if (!current_user_can('manage_options')) return;
    ?>
        <style>
            #wpadminbar .iplr-on>.ab-item {
                background-color: #28a745 !important;
                /* 緑 */
                color: #fff !important;
            }

            #wpadminbar .iplr-on>.ab-item:hover {
                background-color: #218838 !important;
                /* 濃い緑 */
            }

            #wpadminbar .iplr-off>.ab-item {
                background-color: #6c757d !important;
                /* グレー */
                color: #fff !important;
            }
        </style>
<?php
    }
}

// 実行
new IP_Login_Restrictor();
