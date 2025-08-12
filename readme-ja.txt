=== IP Login Restrictor ===
Contributors: gti-inc
Tags: セキュリティ, IP, ログイン, 管理画面, 制限
Requires at least: 5.0
Tested up to: 6.8.2
Stable tag: 1.1.7
License: GPLv2 or later
License URI: https://www.gnu.org/licenses/gpl-2.0.html

IPアドレス（CIDR対応）による WordPress ログイン・管理画面アクセス制限プラグイン。wp-config.php による緊急許可IP設定も可能。

== 説明 ==

このプラグインは、WordPress のログインページ（`wp-login.php`）および管理画面（`wp-admin/`）へのアクセスを、特定の IP アドレスまたは CIDR 範囲で制限できます。

**主な機能：**

- `wp-login.php` や `wp-admin/` へのアクセスを許可された IP のみに制限
- CIDR表記（例：`192.168.1.0/24`）に対応
- 管理画面から有効／無効を切り替え可能（ラジオボタン）
- `wp-config.php` に以下を記述すると緊急IPを許可：  
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`
- 全てのIP制限を一時的に無効化：  
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`
- 管理画面から許可IPリストを編集可能
- アクセス拒否メッセージを **HTML** でカスタマイズ可能（テーマに依存せず、シンプルなHTMLとして出力）
- 本文中で `{ip}`, `{datetime}`, `{site_name}` のトークンが使用可能
- 現在のIPをワンクリックで追加可能
- 管理バーに有効／無効ステータスと現在IPを表示
- アップデート通知＆自動更新（GitHub連携）対応

※ `admin-ajax.php` と `admin-post.php` には影響しません。

== インストール方法 ==

1. プラグインファイルを `/wp-content/plugins/ip-login-restrictor` にアップロードするか、WordPress管理画面からインストールします。
2. 「プラグイン」画面から有効化します。
3. 「IP Login Restrictor」メニューから許可IPを設定します。

== よくある質問 ==

= 緊急IPを許可するには？ =  
`wp-config.php` に以下を追加してください：

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= 一時的にIP制限を解除するには？ =  
`wp-config.php` に以下を追加してください：

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

== スクリーンショット ==

1. 許可IP設定画面（緊急IP説明付き）
2. アクセス拒否メッセージのHTML編集画面

== 変更履歴 ==

= 1.1.6 =
* 管理画面からON/OFF切り替え機能を追加
* アクセス拒否メッセージをHTMLカスタマイズ可能に（テーマ非依存）
* `{ip}`, `{datetime}`, `{site_name}` トークン対応
* デフォルトメッセージに翻訳を追加

= 1.1.1 =
* `REMOVE_WP_LOGIN_IP_ADDRESS` による制限解除機能追加
* LOLIPOP! 固定IPサービスへのリンク追加
* 現在のIP自動入力と緊急アクセス案内追加
* UI改善と細かい修正

= 1.0 =
* 初回リリース

== ライセンス ==
このプラグインは GNU General Public License v2 またはそれ以降のバージョンの下でライセンスされています。

== サードパーティライブラリ ==
* Plugin Update Checker（MITライセンス）  
  https://github.com/YahnisElsts/plugin-update-checker
