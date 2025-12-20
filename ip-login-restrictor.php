<?php

/**
 * Plugin Name: IP Login Restrictor
 * Plugin URI: https://github.com/taman777/ip-login-restrictor
 * Description: 指定された IP アドレス・CIDR だけが WordPress にログイン・管理画面にアクセスできます。wp-config.php に定義すれば緊急避難IPも許可されます。
 * Version: 1.3.0
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
    const OPTION_RESCUE_PARAM     = 'ip_login_restrictor_rescue_param'; // URLパラメータキー
    const OPTION_MSG_BODY     = 'ip_login_restrictor_message_body_html'; // 本文のみHTML
    const OPTION_PREVIEW_MSG  = 'ip_login_restrictor_preview_notice_msg'; // プレビュー中通知メッセージ
    const META_TEMPORARY_IPS  = '_iplr_temporary_ips'; // ページ固有の臨時IP
    const META_TEMPORARY_IPS_MESSAGE = '_iplr_temporary_ips_message'; // ページ固有の拒否メッセージ
    const META_TEMPORARY_IPS_EXPIRE  = '_iplr_temporary_ips_expire';  // ページ固有の制限有効期限

    /** @var string 管理メニューのフック名（load-フックでPOST処理用） */
    private $menu_hook = '';

    /** @var bool IP制限によりログインなしでプレビュー表示中か */
    private $is_preview_via_ip = false;

    public function __construct()
    {
        add_action('plugins_loaded', [$this, 'load_textdomain']);

        // Rescue URL チェック (template_redirect なら安全)
        add_action('template_redirect', [$this, 'handle_rescue_request'], 1);

        // 下書きプレビューの許可（ログインなし・IP制限時のみ）
        add_filter('the_posts', [$this, 'allow_draft_preview'], 10, 2);

        // アクセス制限チェック
        // フロントエンド
        add_action('template_redirect', [$this, 'check_access']);
        // ログイン画面
        add_action('login_init',        [$this, 'check_access']);
        // 管理画面（admin-ajax等も含む）
        add_action('admin_init',        [$this, 'check_access']);

        // プレビュー通知バー（画面下部）
        add_action('wp_footer',         [$this, 'show_preview_notice']);

        add_action('admin_menu',      [$this, 'add_admin_menu']);
        add_action('admin_bar_menu',  [$this, 'add_admin_bar_status'], 100);

        // 全体への警告通知
        add_action('admin_notices',   [$this, 'admin_page_restriction_notice']);

        // 管理バー色付け（有効=緑 / 無効=グレー）
        add_action('admin_head',      [$this, 'output_adminbar_css']);
        add_action('wp_head',         [$this, 'output_adminbar_css']);

        // ページ単位の臨時IP設定用メタボックス
        add_action('add_meta_boxes', [$this, 'add_temporary_ip_metabox']);
        add_action('save_post',      [$this, 'save_temporary_ip_metabox']);

        // 投稿一覧にカスタムカラム追加
        add_filter('manage_posts_columns',       [$this, 'add_temporary_ip_column']);
        add_filter('manage_pages_columns',       [$this, 'add_temporary_ip_column']);
        add_action('manage_posts_custom_column', [$this, 'display_temporary_ip_column'], 10, 2);
        add_action('manage_pages_custom_column', [$this, 'display_temporary_ip_column'], 10, 2);

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
            // 静的メソッドで翻訳済みテンプレをセット
            add_option(self::OPTION_MSG_BODY, self::get_default_body_html_translated());
        }
        if (get_option(self::OPTION_PREVIEW_MSG, null) === null) {
            add_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        }
        if (get_option(self::OPTION_RESCUE_PARAM, null) === null) {
            add_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
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
        delete_option(self::OPTION_RESCUE_PARAM);
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

        // ページ個別の臨時IP設定を確認（フロントエンドの場合）
        $page_temp_ips_active = false;
        $post_id = 0;
        if (!$is_admin_area) {
            $post_id = get_queried_object_id();
            if ($post_id) {
                $enabled_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
                if ($enabled_meta === '1') {
                    // 有効期限のチェック
                    $expire_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
                    if ($expire_meta) {
                        $expire_timestamp = strtotime($expire_meta);
                        if ($expire_timestamp && current_time('timestamp') > $expire_timestamp) {
                            $page_temp_ips_active = false;
                        } else {
                            $page_temp_ips_active = true;
                        }
                    } else {
                        // 期限なし（本来は設定すべきだが、互換性のため許可）
                        $page_temp_ips_active = true;
                    }
                }
            }
        }

        // 管理画面系ではなく、かつフロントエンド制限が無効、かつページ個別制限も無効なら何もしない
        if (!$is_admin_area && !$this->is_frontend_enabled() && !$page_temp_ips_active) {
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

            // ページ固有の臨時IPを追加（有効な場合）
            if ($page_temp_ips_active && $post_id) {
                $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
                if ($temporary_ips) {
                    $temp_ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                    $temp_ips_array = array_filter(array_map('trim', $temp_ips_array));
                    $allowed_ips = array_merge($allowed_ips, $temp_ips_array);
                }
            }
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
            $page_message_html = '';
            if ($post_id) {
                $raw_msg = get_post_meta($post_id, self::META_TEMPORARY_IPS_MESSAGE, true);
                if ($raw_msg) {
                    $page_message_html = '<div class="page-message" style="margin: 15px 0; padding: 10px; background: #fff9c4; border-left: 4px solid #fbc02d; color: #333;">' . esc_html($raw_msg) . '</div>';
                }
            }

            // トークンが含まれていないがメッセージがある場合、末尾に強制展開用として追加
            if ($page_message_html !== '' && strpos($body_html, '{page_message}') === false) {
                // <small>等のタグがある可能性を考慮して単純に末尾に追加
                $body_html .= '{page_message}';
            }

            $replacements = [
                '{ip}'           => esc_html($remote_ip),
                '{datetime}'     => esc_html(date_i18n(get_option('date_format') . ' ' . get_option('time_format'))),
                '{site_name}'    => esc_html(get_bloginfo('name')),
                '{page_message}' => $page_message_html,
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

    /**
     * 下書きプレビューの許可（ログインなし・IP制限時のみ）
     * 参照: https://developer.wordpress.org/reference/hooks/the_posts/
     */
    public function allow_draft_preview($posts, $query)
    {
        // 管理画面や、既に記事が見つかっている場合、メインクエリ以外は対象外
        if (is_admin() || !empty($posts) || !$query->is_main_query()) {
            return $posts;
        }

        // プレビューリクエストかチェック
        $post_id = 0;
        if (isset($_GET['preview']) && $_GET['preview'] === 'true') {
            if (isset($_GET['p'])) {
                $post_id = intval($_GET['p']);
            } elseif (isset($_GET['page_id'])) {
                $post_id = intval($_GET['page_id']);
            }
        }

        if ($post_id > 0) {
            if ($this->is_ip_allowed_for_post($post_id)) {
                $post = get_post($post_id);
                // 下書き、レビュー待ち、予約済みを許可
                if ($post && in_array($post->post_status, ['draft', 'pending', 'future'])) {
                    $this->is_preview_via_ip = true; // フラグを立てる
                    $posts = [$post];
                    // 404を回避
                    $query->is_404 = false;
                    // クエリフラグを適切に設定
                    if ($post->post_type === 'page') {
                        $query->is_page = true;
                    } else {
                        $query->is_single = true;
                    }
                }
            }
        }

        return $posts;
    }

    /**
     * 特定の投稿に対してIPが許可されているか判定
     */
    private function is_ip_allowed_for_post($post_id)
    {
        // プラグイン自体が無効なら、この機能で特別に表示させることはしない（標準のWP動作に任せる）
        if (!$this->is_enabled()) return false;

        $remote_ip = $this->get_client_ip();
        
        // 管理用IPリスト（緊急避難IP含む）
        $admin_ips = get_option(self::OPTION_IPS, []);
        if (defined('WP_LOGIN_IP_ADDRESS')) {
             $emergency_ips = WP_LOGIN_IP_ADDRESS;
             if (is_string($emergency_ips)) {
                 $emergency_ips = preg_split('/[\s,]+/', $emergency_ips, -1, PREG_SPLIT_NO_EMPTY);
             }
             if (is_array($emergency_ips)) {
                 $admin_ips = array_merge($admin_ips, $emergency_ips);
             }
        }

        if ($this->ip_in_allowed_list($remote_ip, $admin_ips)) {
            return true;
        }

        // フロントエンドIPリスト
        if ($this->is_frontend_enabled()) {
            $frontend_ips = get_option(self::OPTION_FRONTEND_IPS, []);
            if ($this->ip_in_allowed_list($remote_ip, $frontend_ips)) {
                return true;
            }
        }

        // ページ個別の臨時IP
        $temp_enabled = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
        if ($temp_enabled === '1') {
            // 有効期限のチェック
            $expire_meta = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
            if ($expire_meta) {
                $expire_timestamp = strtotime($expire_meta);
                if ($expire_timestamp && current_time('timestamp') > $expire_timestamp) {
                    return false;
                }
            }

            $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
            if ($temporary_ips) {
                $temp_ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                $temp_ips_array = array_filter(array_map('trim', $temp_ips_array));
                if ($this->ip_in_allowed_list($remote_ip, $temp_ips_array)) {
                    return true;
                }
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

        // Rescue Key & Param
        if (isset($_POST['ip_login_restrictor_rescue_key'])) {
            $key = sanitize_text_field($_POST['ip_login_restrictor_rescue_key']);
            update_option(self::OPTION_RESCUE_KEY, $key);
        }
        if (isset($_POST['ip_login_restrictor_rescue_param'])) {
            $param = sanitize_text_field($_POST['ip_login_restrictor_rescue_param']);
            // 空の場合はデフォルトに戻す
            if ($param === '') {
                $param = 'iplr_rescue';
            }
            update_option(self::OPTION_RESCUE_PARAM, $param);
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

        // プレビュー通知メッセージ
        if (isset($_POST['ip_login_restrictor_preview_notice_msg'])) {
            update_option(self::OPTION_PREVIEW_MSG, sanitize_text_field($_POST['ip_login_restrictor_preview_notice_msg']));
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
        $param_key = get_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
        if (!isset($_GET[$param_key])) return;

        $input_key = (string)$_GET[$param_key];
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
        $rescue_param = get_option(self::OPTION_RESCUE_PARAM, 'iplr_rescue');
        $rescue_url = $rescue_key ? home_url('/?' . $rescue_param . '=' . $rescue_key) : '';

        $enabled    = $this->is_enabled();
        $frontend_enabled = $this->is_frontend_enabled();
        $admin_ips        = implode("\n", get_option(self::OPTION_IPS, []));
        $frontend_ips     = implode("\n", get_option(self::OPTION_FRONTEND_IPS, []));
        $msg_body   = (string) get_option(self::OPTION_MSG_BODY, '');
        $preview_msg = (string) get_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        $current_ip = esc_html($this->get_client_ip());

        // ページ単位の制限が有効なページを取得
        $temp_pages_query = new WP_Query([
            'post_type'      => ['post', 'page'],
            'posts_per_page' => -1,
            'meta_query'     => [
                [
                    'key'   => self::META_TEMPORARY_IPS . '_enabled',
                    'value' => '1',
                ]
            ],
        ]);
        $active_temp_pages = [];
        if ($temp_pages_query->have_posts()) {
            while ($temp_pages_query->have_posts()) {
                $temp_pages_query->the_post();
                $pid = get_the_ID();
                $expire_at = get_post_meta($pid, self::META_TEMPORARY_IPS_EXPIRE, true);
                
                $is_expired = false;
                $remaining_text = __('No expiration', 'ip-login-restrictor');
                
                if ($expire_at) {
                    $expire_ts = strtotime($expire_at);
                    $now = current_time('timestamp');
                    if ($now > $expire_ts) {
                        $is_expired = true;
                        $remaining_text = '<span style="color:#d63638;font-weight:bold;">' . __('Expired', 'ip-login-restrictor') . '</span>';
                    } else {
                        $diff = $expire_ts - $now;
                        $hours = floor($diff / 3600);
                        $mins  = floor(($diff % 3600) / 60);
                        $remaining_text = sprintf(__('%d hours %d mins left', 'ip-login-restrictor'), $hours, $mins);
                    }
                }

                // 期限切れでも「有効（Enable）」設定になっているものはリストに含める（ただし期限切れ表示付き）
                $active_temp_pages[] = [
                    'id'        => $pid,
                    'title'     => get_the_title(),
                    'slug'      => get_post_field('post_name', $pid),
                    'status'    => get_post_status($pid),
                    'edit_url'  => get_edit_post_link($pid),
                    'expire_at' => $expire_at,
                    'remaining' => $remaining_text,
                    'is_expired'=> $is_expired
                ];
            }
            wp_reset_postdata();
        }
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

                <?php if (!empty($active_temp_pages)): ?>
                    <div class="iplr-active-temp-pages" style="margin-top:20px; background:#fff; border:1px solid #ccd0d4; padding:15px; border-radius:4px;">
                        <h3><?php _e('Active Page Specific Restrictions', 'ip-login-restrictor'); ?></h3>
                        <p class="description"><?php _e('The following pages have page-specific IP restrictions enabled.', 'ip-login-restrictor'); ?></p>
                        <table class="wp-list-table widefat fixed striped" style="margin-top:10px;">
                            <thead>
                                <tr>
                                    <th style="width:60px;">ID</th>
                                    <th><?php _e('Title', 'ip-login-restrictor'); ?></th>
                                    <th style="width:100px;"><?php _e('Post Status', 'ip-login-restrictor'); ?></th>
                                    <th><?php _e('Slug', 'ip-login-restrictor'); ?></th>
                                    <th><?php _e('Remaining Time', 'ip-login-restrictor'); ?></th>
                                    <th style="width:80px;"><?php _e('Edit', 'ip-login-restrictor'); ?></th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach ($active_temp_pages as $p): ?>
                                    <tr>
                                        <td><?php echo $p['id']; ?></td>
                                        <td><strong><a href="<?php echo esc_url($p['edit_url']); ?>"><?php echo esc_html($p['title']); ?></a></strong></td>
                                        <td><?php echo esc_html(get_post_status_object($p['status'])->label); ?></td>
                                        <td><code><?php echo esc_html($p['slug']); ?></code></td>
                                        <td><?php echo $p['remaining']; ?></td>
                                        <td><a href="<?php echo esc_url($p['edit_url']); ?>" class="button button-small"><?php _e('Edit', 'ip-login-restrictor'); ?></a></td>
                                    </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                <?php endif; ?>
                <hr>

                <h2><?php _e('Rescue URL', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('This is your safety net if your IP address changes and you get locked out. Set a secret key below to generate your unique Rescue URL. Accessing that URL will automatically add your new IP to the Admin Whitelist. <b>Please bookmark the generated URL immediately.</b>', 'ip-login-restrictor'); ?>
                </p>
                <p>
                    <label>
                        <?php _e('Rescue Parameter Key:', 'ip-login-restrictor'); ?>
                        <input type="text" name="ip_login_restrictor_rescue_param" value="<?php echo esc_attr($rescue_param); ?>" class="regular-text" placeholder="iplr_rescue">
                    </label>
                </p>
                <p>
                    <label>
                        <?php _e('Rescue Key Value:', 'ip-login-restrictor'); ?>
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

                <div id="iplr-frontend-ips-section" style="<?php echo $frontend_enabled ? '' : 'display:none;'; ?>">
                    <h3><?php _e('Frontend Only Allowed IPs', 'ip-login-restrictor'); ?></h3>
                    <p class="description"><?php _e('These IPs can ONLY access the Frontend (Normal pages). Ignored if Frontend Restriction is disabled.', 'ip-login-restrictor'); ?></p>
                    <textarea name="ip_login_restrictor_frontend_ips" rows="8" cols="60"><?php echo esc_textarea($frontend_ips); ?></textarea>
                    <p>
                        <button type="button" class="button" onclick="addCurrentIP('ip_login_restrictor_frontend_ips')"><?php _e('Add current IP to Frontend List', 'ip-login-restrictor'); ?></button>
                    </p><br>
                </div>

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

                <hr>

                <h2><?php _e('Preview Notice Message', 'ip-login-restrictor'); ?></h2>
                <p class="description">
                    <?php _e('Message shown at the bottom/top of the screen when viewing a draft preview via IP restriction.', 'ip-login-restrictor'); ?>
                </p>
                <input type="text" name="ip_login_restrictor_preview_notice_msg" value="<?php echo esc_attr($preview_msg); ?>" class="regular-text" style="width:100%; max-width:600px;">

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
                    <h3><?php _e('Do you need a static IP address to safely access the admin screen?', 'ip-login-restrictor'); ?></h3>
                    <p>
                        <?php _e('With a static IP, you can maximize IP restriction to enhance security.<br>Recommended for those who want safe and smooth access to the admin screen even from outside or in dynamic IP environments.', 'ip-login-restrictor'); ?>
                    </p>
                    <a href="https://vpn.lolipop.jp/signup?agency_code=f4702aa6f7ddvp" target="_blank" rel="noopener noreferrer" class="iplr-promotion-btn">
                        <?php _e('View LOLIPOP! Static IP Access Service', 'ip-login-restrictor'); ?> <span class="dashicons dashicons-external"></span>
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

            // Toggle Frontend IPs section visibility
            document.querySelectorAll('input[name="ip_login_restrictor_frontend_enabled"]').forEach(function(radio) {
                radio.addEventListener('change', function() {
                    const section = document.getElementById('iplr-frontend-ips-section');
                    if (this.value === '1') {
                        section.style.display = '';
                    } else {
                        section.style.display = 'none';
                    }
                });
            });
        </script>
    <?php
    }

    /** ページ単位の臨時IP設定用メタボックスを追加 */
    public function add_temporary_ip_metabox()
    {
        $post_types = ['post', 'page'];
        foreach ($post_types as $post_type) {
            add_meta_box(
                'iplr_temporary_ips',
                __('IP Login Restrictor - Temporary IPs', 'ip-login-restrictor'),
                [$this, 'render_temporary_ip_metabox'],
                $post_type,
                'side',
                'default'
            );
        }
    }

    /** メタボックスの表示 */
    public function render_temporary_ip_metabox($post)
    {
        wp_nonce_field('iplr_save_temporary_ips', 'iplr_temporary_ips_nonce');
        $temporary_ips = get_post_meta($post->ID, self::META_TEMPORARY_IPS, true);
        $temporary_ips_enabled = get_post_meta($post->ID, self::META_TEMPORARY_IPS . '_enabled', true);
        $expire_at = get_post_meta($post->ID, self::META_TEMPORARY_IPS_EXPIRE, true);

        // デフォルトは無効
        if ($temporary_ips_enabled === '') {
            $temporary_ips_enabled = '0';
        }

        // デフォルトの期限（新規作成時のみ 24時間後）
        if ($expire_at === '' && empty($temporary_ips)) {
            $expire_at = date('Y-m-d\TH:i', current_time('timestamp') + 24 * 3600);
        }

        $is_expired = false;
        if ($expire_at) {
            $is_expired = current_time('timestamp') > strtotime($expire_at);
        }

        $current_ip = esc_html($this->get_client_ip());
        ?>
        <div style="margin-bottom:12px;">
            <label style="display:inline-block;margin-right:12px;">
                <input type="radio" name="iplr_temporary_ips_enabled" value="1" <?php checked($temporary_ips_enabled, '1'); ?>>
                <span style="color:#1f8f3a;font-weight:600;"><?php _e('Enable', 'ip-login-restrictor'); ?></span>
            </label>
            <label style="display:inline-block;">
                <input type="radio" name="iplr_temporary_ips_enabled" value="0" <?php checked($temporary_ips_enabled, '0'); ?>>
                <span style="color:#6c757d;font-weight:600;"><?php _e('Disable', 'ip-login-restrictor'); ?></span>
            </label>
        </div>
        <p class="description">
            <?php _e('Add temporary IP addresses for this page only. One IP per line. CIDR notation is supported.', 'ip-login-restrictor'); ?>
        </p>
        <p class="description" style="margin-top:8px;">
            <?php _e('These IPs will be added to the default allowed IPs when accessing this page.', 'ip-login-restrictor'); ?>
        </p>
        <textarea name="iplr_temporary_ips" rows="6" style="width:100%;margin-top:10px;"><?php echo esc_textarea($temporary_ips); ?></textarea>
        
        <p style="margin-top:12px; font-weight:bold;"><?php _e('Expiration Date/Time:', 'ip-login-restrictor'); ?></p>
        <input type="datetime-local" name="iplr_temporary_ips_expire" value="<?php echo esc_attr($expire_at); ?>" style="width:100%;">
        <p class="description">
            <?php _e('The page IP restriction will be automatically disabled after this time.', 'ip-login-restrictor'); ?>
            <?php if ($is_expired): ?>
                <br><span style="color:#d63638;font-weight:bold;"><?php _e('Status: Expired', 'ip-login-restrictor'); ?></span>
            <?php endif; ?>
        </p>

        <p style="margin-top:12px; font-weight:bold;"><?php _e('Custom Denied Message:', 'ip-login-restrictor'); ?></p>
        <input type="text" name="iplr_temporary_ips_message" value="<?php echo esc_attr(get_post_meta($post->ID, self::META_TEMPORARY_IPS_MESSAGE, true)); ?>" style="width:100%;" placeholder="<?php _e('e.g. Please contact the administrator.', 'ip-login-restrictor'); ?>">
        <p class="description"><?php _e('This message will replace the {page_message} token in the access denied body.', 'ip-login-restrictor'); ?></p>

        <p style="margin-top:8px;">
            <button type="button" class="button button-small" onclick="iplrAddCurrentIP()">
                <?php _e('Add current IP', 'ip-login-restrictor'); ?>
            </button>
            <span style="margin-left:8px;font-size:11px;color:#666;">
                <?php _e('Your IP:', 'ip-login-restrictor'); ?> <?php echo $current_ip; ?>
            </span>
        </p>
        <script>
            function iplrAddCurrentIP() {
                const ip = "<?php echo esc_js($this->get_client_ip()); ?>";
                const textarea = document.querySelector('textarea[name="iplr_temporary_ips"]');
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

    /** メタボックスの保存 */
    public function save_temporary_ip_metabox($post_id)
    {
        // Nonce チェック
        if (!isset($_POST['iplr_temporary_ips_nonce']) || !wp_verify_nonce($_POST['iplr_temporary_ips_nonce'], 'iplr_save_temporary_ips')) {
            return;
        }

        // 自動保存の場合は何もしない
        if (defined('DOING_AUTOSAVE') && DOING_AUTOSAVE) {
            return;
        }

        // 権限チェック
        if (!current_user_can('edit_post', $post_id)) {
            return;
        }


        // 臨時IP有効/無効の保存
        if (isset($_POST['iplr_temporary_ips_enabled'])) {
            $enabled = ($_POST['iplr_temporary_ips_enabled'] === '1') ? '1' : '0';
            update_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', $enabled);
        }

        // 臨時メッセージの保存
        if (isset($_POST['iplr_temporary_ips_message'])) {
            update_post_meta($post_id, self::META_TEMPORARY_IPS_MESSAGE, sanitize_text_field($_POST['iplr_temporary_ips_message']));
        }

        // 臨時IPの保存
        if (isset($_POST['iplr_temporary_ips'])) {
            $temporary_ips = sanitize_textarea_field($_POST['iplr_temporary_ips']);
            update_post_meta($post_id, self::META_TEMPORARY_IPS, $temporary_ips);
        } else {
            delete_post_meta($post_id, self::META_TEMPORARY_IPS);
        }

        // 有効期限の保存
        if (isset($_POST['iplr_temporary_ips_expire'])) {
            $expire_at = sanitize_text_field($_POST['iplr_temporary_ips_expire']);
            update_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, $expire_at);
        }
    }

    /** 投稿一覧にカスタムカラムを追加 */
    public function add_temporary_ip_column($columns)
    {
        $columns['iplr_temporary_ips'] = __('Temporary IPs', 'ip-login-restrictor');
        return $columns;
    }

    /** カスタムカラムの表示 */
    public function display_temporary_ip_column($column, $post_id)
    {
        if ($column === 'iplr_temporary_ips') {
            $temporary_ips = get_post_meta($post_id, self::META_TEMPORARY_IPS, true);
            $temporary_ips_enabled = get_post_meta($post_id, self::META_TEMPORARY_IPS . '_enabled', true);
            
            if ($temporary_ips) {
                $ips_array = preg_split("/\r\n|\r|\n/", $temporary_ips);
                $ips_array = array_filter(array_map('trim', $ips_array));
                $count = count($ips_array);
                
                $expire_at = get_post_meta($post_id, self::META_TEMPORARY_IPS_EXPIRE, true);
                $is_expired = $expire_at && (current_time('timestamp') > strtotime($expire_at));

                // スイッチの状態で色を変える
                if ($temporary_ips_enabled === '1' && !$is_expired) {
                    echo '<span style="color:#1f8f3a;font-weight:600;">✓ ' . sprintf(_n('%d IP', '%d IPs', $count, 'ip-login-restrictor'), $count) . '</span>';
                } elseif ($is_expired) {
                    echo '<span style="color:#d63638;font-weight:600;">! ' . __('Expired', 'ip-login-restrictor') . '</span>';
                } else {
                    echo '<span style="color:#999;font-weight:600;">✗ ' . sprintf(_n('%d IP', '%d IPs', $count, 'ip-login-restrictor'), $count) . '</span>';
                }
                
                echo '<div style="font-size:11px;color:#666;margin-top:2px;">' . esc_html(implode(', ', array_slice($ips_array, 0, 3)));
                if ($count > 3) {
                    echo '...';
                }
                if ($expire_at) {
                    echo '<br>' . esc_html($expire_at);
                }
                echo '</div>';
            } else {
                echo '<span style="color:#999;">—</span>';
            }
        }
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

    /**
     * IP制限下でのプレビュー通知を表示
     */
    public function show_preview_notice()
    {
        if (!$this->is_preview_via_ip) return;

        $msg          = get_option(self::OPTION_PREVIEW_MSG, __('You are viewing this preview because your IP is whitelisted.', 'ip-login-restrictor'));
        $toggle_label = __('Move', 'ip-login-restrictor');
        ?>
        <div id="iplr-preview-notice" onclick="this.classList.toggle('iplr-top')" title="<?php echo esc_attr($toggle_label); ?>">
            <div class="iplr-notice-content">
                <span class="dashicons dashicons-shield iplr-icon-shield"></span>
                <span class="iplr-text-msg"><?php echo esc_html($msg); ?></span>
                <span class="iplr-toggle-btn">
                    <span class="dashicons dashicons-sort"></span>
                    <span class="iplr-btn-text"><?php echo esc_html($toggle_label); ?></span>
                </span>
            </div>
        </div>
        <style>
            #iplr-preview-notice {
                position: fixed;
                bottom: 0;
                left: 0;
                width: 100%;
                background: rgba(30, 30, 30, 0.85);
                color: #fff;
                padding: 10px 0;
                text-align: center;
                font-size: 14px;
                z-index: 999999;
                backdrop-filter: blur(10px);
                -webkit-backdrop-filter: blur(10px);
                border-top: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 -4px 15px rgba(0, 0, 0, 0.3);
                font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
                cursor: pointer;
                transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
                user-select: none;
            }
            #iplr-preview-notice:hover {
                background: rgba(45, 45, 45, 0.95);
            }
            #iplr-preview-notice.iplr-top {
                bottom: auto;
                top: 0;
                border-top: none;
                border-bottom: 1px solid rgba(255, 255, 255, 0.15);
                box-shadow: 0 4px 15px rgba(0, 0, 0, 0.3);
            }
            .iplr-notice-content {
                display: flex;
                align-items: center;
                justify-content: center;
                gap: 10px;
                max-width: 1200px;
                margin: 0 auto;
                padding: 0 20px;
            }
            .iplr-icon-shield {
                color: #4caf50;
                font-size: 20px;
                width: 20px;
                height: 20px;
            }
            .iplr-toggle-btn {
                display: inline-flex;
                align-items: center;
                gap: 5px;
                background: rgba(255, 255, 255, 0.15);
                padding: 4px 10px;
                border-radius: 4px;
                font-size: 12px;
                margin-left: 10px;
                transition: background 0.2s;
            }
            #iplr-preview-notice:hover .iplr-toggle-btn {
                background: rgba(255, 255, 255, 0.25);
            }
            .iplr-btn-text {
                font-weight: 600;
                text-transform: uppercase;
                letter-spacing: 0.5px;
            }
            @media (max-width: 600px) {
                .iplr-btn-text { display: none; }
                .iplr-text-msg { font-size: 12px; }
            }
            /* 管理バーがある場合のボディパディング調整（簡易的） */
            body.iplr-preview-active { padding-bottom: 50px; }
            body.iplr-preview-active-top { padding-top: 50px; }
        </style>
        <script>
            (function() {
                const notice = document.getElementById('iplr-preview-notice');
                const body = document.body;
                body.classList.add('iplr-preview-active');
                
                notice.addEventListener('click', function() {
                    if (this.classList.contains('iplr-top')) {
                        body.classList.remove('iplr-preview-active');
                        body.classList.add('iplr-preview-active-top');
                    } else {
                        body.classList.add('iplr-preview-active');
                        body.classList.remove('iplr-preview-active-top');
                    }
                });
            })();
        </script>
        <?php
    }

    /**
     * 管理画面にページ単位のIP制御があることを通知
     */
    public function admin_page_restriction_notice()
    {
        if (!current_user_can('manage_options')) return;

        // ページ単位の制限が有効なページ（期限内）があるかチェック
        $args = [
            'post_type'      => ['post', 'page'],
            'posts_per_page' => 1,
            'fields'         => 'ids',
            'meta_query'     => [
                [
                    'key'   => self::META_TEMPORARY_IPS . '_enabled',
                    'value' => '1',
                ]
            ],
        ];
        
        $query = new WP_Query($args);
        $has_active = false;

        if ($query->have_posts()) {
            foreach ($query->posts as $pid) {
                $expire_at = get_post_meta($pid, self::META_TEMPORARY_IPS_EXPIRE, true);
                if (!$expire_at || strtotime($expire_at) > current_time('timestamp')) {
                    $has_active = true;
                    break;
                }
            }
        }

        if ($has_active) {
            echo '<div class="notice notice-error" style="background-color: #d63638; border-left-color: #9b2021; color: #fff; padding: 12px; margin-left: 0; margin-right: 0;">';
            echo '<p style="margin: 0; font-weight: bold; font-size: 15px; display: flex; align-items: center; gap: 8px;">';
            echo '<span class="dashicons dashicons-shield-alt"></span>';
            echo esc_html__('Page-specific IP Restriction Active', 'ip-login-restrictor');
            echo ' <a href="' . admin_url('admin.php?page=ip-login-restrictor') . '" style="color: #fff; text-decoration: underline; margin-left: 15px; font-weight: normal; font-size: 13px;">' . esc_html__('View Details', 'ip-login-restrictor') . '</a>';
            echo '</p></div>';
        }
    }
}

} // End if class_exists

// 実行
new IP_Login_Restrictor();
