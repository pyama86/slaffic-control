## slack

slackのApp Manifestを使って、Slack Appを作成します。

```yaml
{
    "display_information": {
        "name": "slaffic-control"
    },
    "features": {
        "bot_user": {
            "display_name": "slaffic-control",
            "always_online": false
        }
    },
    "oauth_config": {
        "scopes": {
            "bot": [
                "app_mentions:read",
                "chat:write",
                "usergroups:read",
                "users:read",
                "reactions:read"
            ]
        }
    },
    "settings": {
        "event_subscriptions": {
            "request_url": "https://your endpoint/slack/events",
            "bot_events": [
                "app_mention",
                "reaction_added",
                "reaction_removed",
                "message:im",
            ]
        },
        "interactivity": {
            "is_enabled": true,
            "request_url": "https://your endpoint/slack/interactions"
        },
        "org_deploy_enabled": false,
        "socket_mode_enabled": false,
        "token_rotation_enabled": false
    }
}
```
