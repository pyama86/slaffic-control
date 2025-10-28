## slack

slackのApp Manifestを使って、Slack Appを作成します。

```json
{
    "display_information": {
        "name": "slaffic-control",
        "description": "your description here",
        "background_color": "#13328f"
    },
    "features": {
        "bot_user": {
            "display_name": "slaffic-control-bot",
            "always_online": true
        }
    },
    "oauth_config": {
        "scopes": {
            "bot": [
                "app_mentions:read",
                "chat:write",
                "im:history",
                "reactions:read",
                "usergroups:read",
                "users:read",
                "channels:history",
                "groups:history",
                "mpim:history"
            ]
        }
    },
    "settings": {
        "event_subscriptions": {
            "bot_events": [
                "app_mention",
                "message.im",
                "reaction_added",
                "reaction_removed"
            ]
        },
        "interactivity": {
            "is_enabled": true
        },
        "org_deploy_enabled": false,
        "socket_mode_enabled": true,
        "token_rotation_enabled": false
    }
}

```
