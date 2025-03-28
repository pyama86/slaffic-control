# slaffic-control

`slaffic-control` は、Slack ワークスペース内での問い合わせ管理を行う Go 言語製のボットです。ユーザーが問い合わせを作成したり、メンションを管理したり、通知を受け取ったりすることができます。また、担当者のローテーション機能も備えており、指定された曜日に自動的に担当を切り替えることができます。

## 機能

- **問い合わせ管理**: ユーザーが問い合わせを作成し、その優先度を設定できます。問い合わせ内容はデータベースに保存されます。
- **メンション管理**: ユーザーやグループに対して、問い合わせが投稿されると自動的に通知を送る設定を行えます。
- **問い合わせ履歴**: 過去の問い合わせ内容を確認でき、詳細も閲覧可能です。
- **自動ローテーション**: 担当者を自動的にローテーションし、指定された曜日に切り替えます。

## 必要条件

- Go 1.16 以上
- SQLite（データベース用）
- Slack Socket Mode

## 環境変数
```
export SLACK_BOT_TOKEN=<your_slack_bot_token>
export SLACK_APP_TOKEN=<your_slack_app_token>
export SLACK_WORKSPACE_URL=<your_slack_workspace_url>
export DB_PATH=<path_to_your_database>  # オプション、デフォルトは ./db/slaffic_control.db
export DEFAULT_CHANNEL=<default_channel> # オプション、例: "#general"
export LISTEN_SOCKET=<listen_socket> # オプション、デフォルトは ":3000"
```
#### DynamoDB の設定
```
export DB_DRIVER=dynamodb
# テーブル名のプレフィクスかテーブル名を指定してください
export DYNAMO_TABLE_NAME_PREFIX=<your prefix>
or
export DYNAMO_INQUIRY_TABLE_NAME=<your inquiry table name>
export DYNAMO_MENTION_SETTING_TABLE_NAME=<your mention setting table name>
```

## 必要な OAuth スコープ

`slaffic-control` を使用するには、以下の OAuth スコープが必要です：

- `app_mentions:read`: `@slaffic-control` がメンションされているメッセージを表示する権限
- `chat:write`: `@slaffic-control` としてメッセージを送信する権限
- `usergroups:read`: ワークスペース内のユーザーグループを表示する権限
- `users:read`: ワークスペース内のユーザーを表示する権限

これらのスコープを設定することで、ボットが適切に機能します。

## ライセンス
このプロジェクトは MIT ライセンスの下で公開されています。

## 作者
- pyama86
