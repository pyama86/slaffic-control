# slaffic-control

`slaffic-control` は、Slack ワークスペース内での問い合わせ管理を行う Go 言語製のボットです。ユーザーが問い合わせを作成したり、メンションを管理したり、通知を受け取ったりすることができます。また、担当者のローテーション機能も備えており、指定された曜日に自動的に担当を切り替えることができます。

## 機能

- **問い合わせ管理**: ユーザーが問い合わせを作成し、その優先度を設定できます。問い合わせ内容はデータベースに保存されます。
- **メンション管理**: ユーザーやグループに対して、問い合わせが投稿されると自動的に通知を送る設定を行えます。
- **問い合わせ履歴**: 過去の問い合わせ内容を確認でき、詳細も閲覧可能です。
- **自動ローテーション**: 担当者を自動的にローテーションし、指定された曜日に切り替えます。

## 必要条件

- Go 1.16 以上
- Slack ボットトークンとサイニングシークレット（`SLACK_BOT_TOKEN` と `SLACK_SIGNING_SECRET`）
- SQLite（データベース用）

## 環境変数
```
export SLACK_BOT_TOKEN=<your_slack_bot_token>
export SLACK_SIGNING_SECRET=<your_slack_signing_secret>
export SLACK_WORKSPACE_URL=<your_slack_workspace_url>
export DB_PATH=<path_to_your_database>  # オプション、デフォルトは ./db/slaffic_control.db
export DEFAULT_CHANNEL=<default_channel> # オプション、例: "#general"
```

## API エンドポイント
リクエストはサイニングシークレットで検証されます。

- /slack/events
Slack イベント（メンションなど）を受け取り、Slack チャンネルとのやり取りを行います。

- /slack/interactions
Slack のブロックキットからのインタラクション（フォーム送信など）を処理します。

## ライセンス
このプロジェクトは MIT ライセンスの下で公開されています。

## 作者
- pyama86
