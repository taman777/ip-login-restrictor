=== IP Login Restrictor ===  
Contributors: gti-inc  
Tags: セキュリティ, IP, ログイン, 管理画面, 制限  
Requires at least: 5.0  
Tested up to: 6.5  
Stable tag: 1.1.3
License: GPLv2 or later  
License URI: https://www.gnu.org/licenses/gpl-2.0.html  

IPアドレス（CIDR対応）による WordPress ログイン・管理画面アクセス制限プラグイン。wp-config.php による緊急許可IP設定も可能。

== 説明 ==

このプラグインは、WordPress のログインページおよび管理画面へのアクセスを、特定の IP アドレスまたは CIDR 範囲で制限できます。

**主な機能：**

- `wp-login.php` や `wp-admin/` へのアクセスを許可された IP のみに制限  
- CIDR表記（例：`192.168.1.0/24`）に対応  
- `wp-config.php` に以下を記述すると緊急IPを許可：  
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`  
- IP制限を一時的に無効化：  
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`  
- 管理画面から許可IPリストを編集可能  
- 許可IPからのアクセス時は通常通りログイン可能  
- `admin-ajax.php` や `admin-post.php` には影響しない（制限対象外）

== ライセンス ==  
このプラグインは GNU General Public License v2 またはそれ以降のバージョンの下でライセンスされています。

== サードパーティライブラリ ==  
このプラグインは以下のサードパーティライブラリを使用しています：

* Plugin Update Checker（MITライセンス）  
  https://github.com/YahnisElsts/plugin-update-checker

== インストール方法 ==

1. プラグインファイルを `/wp-content/plugins/ip-login-restrictor` ディレクトリにアップロードするか、WordPress管理画面からインストールしてください。  
2. WordPress の「プラグイン」画面から有効化します。  
3. 「IP Login Restrictor」メニューから許可IPの設定を行ってください。

== よくある質問 ==

= 緊急IPを許可するには？ =  
`wp-config.php` に以下を追加してください：

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`

= 一時的にIP制限をすべて解除したい場合は？ =  
以下の1行を `wp-config.php` に追加してください：

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`

== スクリーンショット ==

1. 許可IP設定画面（緊急IPの説明付き）  
2. 緊急アクセス用のコード表示と案内  

== 変更履歴 ==

= 1.1.1 =  
* `REMOVE_WP_LOGIN_IP_ADDRESS` による制限解除機能を追加  
* LOLIPOP! 固定IPサービスへのリンクを追加  
* 現在のIP自動入力機能と緊急アクセス補助を追加  
* UI改善などの細かな修正

= 1.0 =  
* 初回リリース
