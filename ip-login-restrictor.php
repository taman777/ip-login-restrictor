<?php

/**
 * Plugin Name: IP Login Restrictor
 * Plugin URI: https://github.com/taman777/ip-login-restrictor
 * Description: 指定された IP アドレス・CIDR だけが WordPress にログイン・管理画面にアクセスできます。wp-config.php に定義すれば緊急避難IPも許可されます。
 * Version: 1.2.0
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

if (!class_exists('IP_Login_Restrictor')) {

class IP_Login_Restrictor
{

    const OPTION_IPS          = 'ip_login_restrictor_ips';
    const OPTION_FRONTEND_IPS = 'ip_login_restrictor_frontend_ips';
    const OPTION_ENABLED      = 'ip_login_restrictor_enabled'; // '1' or '0'
    const OPTION_FRONTEND_ENABLED = 'ip_login_restrictor_frontend_enabled'; // '1' or '0'
    const OPTION_RESCUE_KEY       = 'ip_login_restrictor_rescue_key';
    const OPTION_MSG_BODY     = 'ip_login_restrictor_message_body_html'; // 本文のみHTML

    /** @var string 管理メニューのフック名（load-フックでPOST処理用） */
    private $menu_hook = '';

    public function __construct()
    {
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        // Rescue URL チェック (template_redirect なら安全)
        add_action('template_redirect', [$this, 'handle_rescue_request'], 1);

        // アクセス制限チェック
        // フロントエンド
        add_action('template_redirect', [$this, 'check_access']);
        // ログイン画面
        add_action('login_init',        [$this, 'check_access']);
        // 管理画面（admin-ajax等も含む）
        add_action('admin_init',        [$this, 'check_access']);

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
        if (get_option(self::OPTION_FRONTEND_ENABLED, null) === null) {
            add_option(self::OPTION_FRONTEND_ENABLED, '0');
        }
        if (get_option(self::OPTION_IPS, null) === null) {
            add_option(self::OPTION_IPS, []);
        }
        if (get_option(self::OPTION_FRONTEND_IPS, null) === null) {
            add_option(self::OPTION_FRONTEND_IPS, []);
        }
        if (get_option(self::OPTION_MSG_BODY, null) === null) {
            // インスタンスを作って翻訳済みテンプレをセット
            // 静的メソッドで翻訳済みテンプレをセット
            add_option(self::OPTION_MSG_BODY, self::get_default_body_html_translated());
        }
    }

    /** アンインストール時: 設定削除 */
    public static function uninstall()
    {
        delete_option(self::OPTION_IPS);
        delete_option(self::OPTION_FRONTEND_IPS);
        delete_option(self::OPTION_ENABLED);
        delete_option(self::OPTION_FRONTEND_ENABLED);
        delete_option(self::OPTION_RESCUE_KEY);
        delete_option(self::OPTION_MSG_BODY);
    }

    /** 現在有効か */
    private function is_enabled()
    {
        return get_option(self::OPTION_ENABLED, '0') === '1';
    }

    /** フロントエンド制限が有効か */
    private function is_frontend_enabled()
    {
        return get_option(self::OPTION_FRONTEND_ENABLED, '0') === '1';
    }

    /** アクセスチェック本体（常にプレーンHTMLで安全に返す） */
    public function check_access()
    {
        if (!$this->is_enabled()) return;
        if (defined('REMOVE_WP_LOGIN_IP_ADDRESS') && REMOVE_WP_LOGIN_IP_ADDRESS === true) return;

        // Ajax/post は除外
        if ($this->is_ajax_or_post()) return;

        // 対象エリア判定
        $is_admin_area = is_admin() || $this->is_login_page();

        // 管理画面系ではなく、かつフロントエンド制限が無効なら何もしない
        if (!$is_admin_area && !$this->is_frontend_enabled()) {
            return;
        }

        $admin_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
             // 緊急避難IP対応（カンマ区切り/配列対応）
             $emergency_ips = WP_LOGIN_IP_ADDRESS;
             if (is_string($emergency_ips)) {
                 $emergency_ips = preg_split('/[\s,]+/', $emergency_ips, -1, PREG_SPLIT_NO_EMPTY);
             }
             if (is_array($emergency_ips)) {
                 $admin_ips = array_merge($admin_ips, $emergency_ips);
             } elseif (is_string($emergency_ips) && $emergency_ips !== '') {
                  $admin_ips[] = $emergency_ips;
             }
        }

        if ($is_admin_area) {
            // 管理画面エリア: 管理用IPリストのみ
            $allowed_ips = $admin_ips;
        } else {
            // フロントエンド: 管理用 + フロント用
            $frontend_ips = get_option(self::OPTION_FRONTEND_IPS, []);
            $allowed_ips  = array_merge($admin_ips, $frontend_ips);
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

        // Rescue Key
        if (isset($_POST['ip_login_restrictor_rescue_key'])) {
            $key = sanitize_text_field($_POST['ip_login_restrictor_rescue_key']);
            update_option(self::OPTION_RESCUE_KEY, $key);
        }

        // 有効/無効
        if (isset($_POST['ip_login_restrictor_enabled'])) {
            $enabled = ($_POST['ip_login_restrictor_enabled'] === '1') ? '1' : '0';
            update_option(self::OPTION_ENABLED, $enabled);
        }

        // フロントエンド制限
        if (isset($_POST['ip_login_restrictor_frontend_enabled'])) {
            $frontend_enabled = ($_POST['ip_login_restrictor_frontend_enabled'] === '1') ? '1' : '0';
            update_option(self::OPTION_FRONTEND_ENABLED, $frontend_enabled);
        }

        // 許可IP (Admin)
        if (isset($_POST['ip_login_restrictor_ips'])) {
            $lines = preg_split("/\r\n|\r|\n/", (string) $_POST['ip_login_restrictor_ips']);
            $ips   = array_filter(array_map('trim', array_map('sanitize_text_field', $lines)));
            update_option(self::OPTION_IPS, $ips);
        }

        // 許可IP (Frontend)
        if (isset($_POST['ip_login_restrictor_frontend_ips'])) {
            $lines = preg_split("/\r\n|\r|\n/", (string) $_POST['ip_login_restrictor_frontend_ips']);
            $ips   = array_filter(array_map('trim', array_map('sanitize_text_field', $lines)));
            update_option(self::OPTION_FRONTEND_IPS, $ips);
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

    /** 救済リクエスト処理 */
    public function handle_rescue_request()
    {
        if (!isset($_GET['iplr_rescue'])) return;

        $input_key = (string)$_GET['iplr_rescue'];
        $stored_key = get_option(self::OPTION_RESCUE_KEY, '');

        if ($stored_key !== '' && $input_key === $stored_key) {
            $ip = $this->get_client_ip();
            $ips = get_option(self::OPTION_IPS, []);
            
            // 既にリストにあるかチェック（IP or CIDR）
            if (!$this->ip_in_allowed_list($ip, $ips)) {
                $ips[] = $ip;
                update_option(self::OPTION_IPS, $ips);
                $msg = sprintf(__('Success! IP %s has been added to the whitelist.', 'ip-login-restrictor'), $ip);
            } else {
                $msg = sprintf(__('IP %s is already in the whitelist.', 'ip-login-restrictor'), $ip);
            }

            // 完了メッセージを表示してログインへ
            wp_die(
                '<h1>' . esc_html__('Rescue Mode', 'ip-login-restrictor') . '</h1>' .
                '<p>' . esc_html($msg) . '</p>' .
                '<p><a href="' . esc_url(wp_login_url()) . '">' . esc_html__('Proceed to Login', 'ip-login-restrictor') . '</a></p>',
                __('Rescue Mode', 'ip-login-restrictor'),
                ['response' => 200]
            );
        }
    }

    /** 設定ページ（描画のみ。本文はtextareaでHTML可） */
    public function settings_page()
    {
        if (!current_user_can('manage_options')) return;

        if (isset($_GET['settings-updated']) && $_GET['settings-updated'] === 'true') {
            echo '<div class="updated"><p>' . esc_html__('Settings saved.', 'ip-login-restrictor') . '</p></div>';
        }

        $rescue_key = get_option(self::OPTION_RESCUE_KEY, '');
        $rescue_url = $rescue_key ? home_url('/?iplr_rescue=' . $rescue_key) : '';

        $enabled    = $this->is_enabled();
        $frontend_enabled = $this->is_frontend_enabled();
        $admin_ips        = implode("\n", get_option(self::OPTION_IPS, []));
        $frontend_ips     = implode("\n", get_option(self::OPTION_FRONTEND_IPS, []));
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

                <h2><?php _e('Frontend Restriction', 'ip-login-restrictor'); ?></h2>
                <label style="display:inline-block;margin-right:16px;">
                    <input type="radio" name="ip_login_restrictor_frontend_enabled" value="1" <?php checked($frontend_enabled, true); ?>>
                    <span style="color:#1f8f3a;font-weight:700;"><?php _e('Restrict Frontend', 'ip-login-restrictor'); ?></span>
                </label>
                <label style="display:inline-block;">
                    <input type="radio" name="ip_login_restrictor_frontend_enabled" value="0" <?php checked($frontend_enabled, false); ?>>
                    <span style="color:#6c757d;font-weight:700;"><?php _e('Allow All (Default)', 'ip-login-restrictor'); ?></span>
                </label>
                <p class="description">
                    <?php _e('If enabled, normal pages (frontend) will also be restricted by the same IP whitelist. (Main plugin status must be Enabled)', 'ip-login-restrictor'); ?>
                </p>
                <hr>

                <h2><?php _e('Rescue URL', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('This is your safety net if your IP address changes and you get locked out. Set a secret key below to generate your unique Rescue URL. Accessing that URL will automatically add your new IP to the Admin Whitelist. **Please bookmark the generated URL immediately.**', 'ip-login-restrictor'); ?>
                </p>
                <p>
                    <label>
                        <?php _e('Rescue Key:', 'ip-login-restrictor'); ?>
                        <input type="text" name="ip_login_restrictor_rescue_key" value="<?php echo esc_attr($rescue_key); ?>" class="regular-text" placeholder="e.g. secret-key-123">
                    </label>
                </p>
                <?php if ($rescue_url): ?>
                    <p style="background:#fff;padding:10px;border:1px solid #ddd;display:inline-block;">
                        <strong><?php _e('Your Rescue URL:', 'ip-login-restrictor'); ?></strong><br>
                        <code><a href="<?php echo esc_url($rescue_url); ?>" target="_blank"><?php echo esc_html($rescue_url); ?></a></code>
                    </p>
                <?php endif; ?>
                
                <hr>

                <h3><?php _e('Admin & Login Allowed IPs', 'ip-login-restrictor'); ?></h3>
                <p class="description"><?php _e('These IPs can access EVERYTHING (Admin, Login, and Frontend).', 'ip-login-restrictor'); ?></p>
                <textarea name="ip_login_restrictor_ips" rows="8" cols="60"><?php echo esc_textarea($admin_ips); ?></textarea>
                <p>
                    <button type="button" class="button" onclick="addCurrentIP('ip_login_restrictor_ips')"><?php _e('Add current IP to Admin List', 'ip-login-restrictor'); ?></button>
                    <span style="margin-left:10px;"><?php _e('Your IP:', 'ip-login-restrictor'); ?> <?php echo $current_ip; ?></span>
                </p>

                <h3><?php _e('Frontend Only Allowed IPs', 'ip-login-restrictor'); ?></h3>
                <p class="description"><?php _e('These IPs can ONLY access the Frontend (Normal pages). Ignored if Frontend Restriction is disabled.', 'ip-login-restrictor'); ?></p>
                <textarea name="ip_login_restrictor_frontend_ips" rows="8" cols="60"><?php echo esc_textarea($frontend_ips); ?></textarea>
                <p>
                    <button type="button" class="button" onclick="addCurrentIP('ip_login_restrictor_frontend_ips')"><?php _e('Add current IP to Frontend List', 'ip-login-restrictor'); ?></button>
                </p><br>

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
            <style>
                .iplr-promotion-box {
                    background: #f0f6fc;
                    border: 1px solid #cce5ff;
                    border-left: 4px solid #0073aa;
                    border-radius: 4px;
                    padding: 20px;
                    margin-top: 30px;
                    display: flex;
                    align-items: center;
                    gap: 20px;
                    box-shadow: 0 1px 3px rgba(0,0,0,0.05);
                }
                .iplr-promotion-icon .dashicons {
                    font-size: 48px;
                    width: 48px;
                    height: 48px;
                    color: #0073aa;
                }
                .iplr-promotion-content h3 {
                    margin: 0 0 8px;
                    font-size: 1.2em;
                    color: #1d2327;
                }
                .iplr-promotion-content p {
                    margin: 0 0 12px;
                    color: #50575e;
                    font-size: 14px;
                }
                .iplr-promotion-btn {
                    display: inline-flex;
                    align-items: center;
                    background: #d63638; /* 目立つ色に */
                    color: #fff;
                    text-decoration: none;
                    padding: 8px 18px;
                    border-radius: 4px;
                    font-weight: 600;
                    font-size: 14px;
                    transition: all 0.2s ease;
                }
                .iplr-promotion-btn:hover {
                    background: #b32d2e;
                    color: #fff;
                    transform: translateY(-1px);
                }
                .iplr-promotion-btn .dashicons {
                    margin-left: 6px;
                    font-size: 16px;
                    width: 16px;
                    height: 16px;
                    line-height: 1.4;
                }
            </style>
            <div class="iplr-promotion-box">
                <div class="iplr-promotion-icon">
                    <span class="dashicons dashicons-shield-alt"></span>
                </div>
                <div class="iplr-promotion-content">
                    <h3>安心して管理画面にアクセスするために固定IPが必要ですか？</h3>
                    <p>
                        固定IPがあれば、IP制限を最大限に活用してセキュリティを強化できます。<br>
                        外出先や動的IP環境でも、安全かつスムーズに管理画面へアクセスしたい方へおすすめです。
                    </p>
                    <a href="https://vpn.lolipop.jp/" target="_blank" rel="noopener noreferrer" class="iplr-promotion-btn">
                        LOLIPOP! 固定IPアクセス サービスを見る <span class="dashicons dashicons-external"></span>
                    </a>
                </div>
            </div>
        </div>
        <script>
            function addCurrentIP(targetName) {
                const ip = "<?php echo esc_js($this->get_client_ip()); ?>";
                const textarea = document.querySelector('textarea[name="' + targetName + '"]');
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
        $frontend_enabled = $this->is_frontend_enabled();

        if ($enabled) {
            $status_text = __('Enabled', 'ip-login-restrictor');
            if ($frontend_enabled) {
                $status_text .= ' ' . __('(+Frontend)', 'ip-login-restrictor');
            }
        } else {
            $status_text = __('Disabled', 'ip-login-restrictor');
        }

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

} // End if class_exists

// 実行
new IP_Login_Restrictor();
