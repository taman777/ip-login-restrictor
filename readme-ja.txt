=== IP Login Restrictor ===  
Contributors: gti-inc  
Tags: セキュリティ, IP, ログイン, 管理画面, 制限  
Requires at least: 5.0  
Tested up to: 6.5  
Stable tag: 1.1.6
License: GPLv2 or later  
License URI: https://www.gnu.org/licenses/gpl-2.0.html  

IPアドレス（CIDR対応）による WordPress ログイン・管理画面アクセス制限プラグイン。  
wp-config.php による緊急許可IP設定や、一時的な制限解除も可能。  
有効/無効切替、管理バー表示、HTML対応の拒否メッセージ機能を追加。

== 説明 ==

このプラグインは、WordPress のログインページおよび管理画面へのアクセスを、  
特定の IP アドレスまたは CIDR 範囲で制限できます。

**主な機能：**

- `wp-login.php` や `wp-admin/` へのアクセスを許可された IP のみに制限  
- CIDR表記（例：`192.168.1.0/24`）に対応  
- **管理画面で有効/無効を切り替え可能（ラジオボタン）**  
- **管理バーに有効/無効ステータスを色付き表示（有効=緑、無効=グレー）し、有効時は現在のIPも表示**  
- `wp-config.php` に以下を記述すると緊急IPを許可：  
  `define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`  
- IP制限を一時的に無効化：  
  `define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`  
- **アクセス拒否メッセージをHTMLでカスタマイズ可能（テーマのheader/footer内に表示）**  
- **メッセージ内で `{ip}`, `{datetime}`, `{site_name}` のトークンが使用可能**  
- 管理画面から許可IPリストを編集可能  
- 現在のアクセス元IPをワンクリックで追加可能  
- 許可IPからのアクセス時は通常通りログイン可能  
- `admin-ajax.php` や `admin-post.php` は制限対象外  
- LOLIPOP! 固定IPアクセスサービスへのリンク付き  

== ライセンス ==  
このプラグインは GNU General Public License v2 またはそれ以降のバージョンの下でライセンスされています。

== サードパーティライブラリ ==  
このプラグインは以下のサードパーティライブラリを使用しています：  

* Plugin Update Checker（MITライセンス）  
  https://github.com/YahnisElsts/plugin-update-checker  

== インストール方法 ==

1. プラグインファイルを `/wp-content/plugins/ip-login-restrictor` ディレクトリにアップロードするか、WordPress管理画面からインストールしてください。  
2. WordPress の「プラグイン」画面から有効化します（初期状態は無効）。  
3. 「IP Login Restrictor」メニューから許可IPやアクセス拒否メッセージを設定してください。  

== よくある質問 ==

= 緊急IPを許可するには？ =  
`wp-config.php` に以下を追加してください：  

`define('WP_LOGIN_IP_ADDRESS', '123.123.123.123');`  

= 一時的にIP制限をすべて解除したい場合は？ =  
以下の1行を `wp-config.php` に追加してください：  

`define('REMOVE_WP_LOGIN_IP_ADDRESS', true);`  

= アクセス拒否メッセージでHTMLは使えますか？ =  
はい。テーマの header/footer 内にそのまま表示されます。  
`{ip}`, `{datetime}`, `{site_name}` のトークンが利用可能です。  

== スクリーンショット ==

1. 許可IP設定画面（有効/無効切替、現在のIP追加ボタン付き）  
2. 管理バーに有効/無効と現在のIPを表示（有効時のみIP表示）  

== 変更履歴 ==

= 1.1.6 =  
* 有効/無効切替（ラジオボタン）機能を追加  
* 管理バーにステータス表示（有効=緑、無効=グレー）  
* 有効時に現在のアクセス元IPを管理バーに表示  
* アクセス拒否メッセージをHTML対応化（テーマheader/footer内表示）  
* メッセージトークン `{ip}`, `{datetime}`, `{site_name}` を追加  

= 1.1.1 =  
* `REMOVE_WP_LOGIN_IP_ADDRESS` による制限解除機能を追加  
* LOLIPOP! 固定IPサービスへのリンクを追加  
* 現在のIP自動入力機能と緊急アクセス補助を追加  
* UI改善などの細かな修正  

= 1.0 =  
* 初回リリース  
