## DynamoDB

### テーブル定義
2つのテーブルを作成します。

- slafiic_control_inquiries

```json
{
    "Table": {
        "AttributeDefinitions": [
            {
                "AttributeName": "bot_id",
                "AttributeType": "S"
            },
            {
                "AttributeName": "timestamp",
                "AttributeType": "S"
            },
            {
                "AttributeName": "done",
                "AttributeType": "N"
            }
        ],
        "TableName": "slaffic_control_inquiries",
        "KeySchema": [
            {
                "AttributeName": "bot_id",
                "KeyType": "HASH"
            },
            {
                "AttributeName": "timestamp",
                "KeyType": "RANGE"
            }
        ],
        "GlobalSecondaryIndexes": [
            {
                "IndexName": "BotIdDoneIndex",
                "KeySchema": [
                    {
                        "AttributeName": "bot_id",
                        "KeyType": "HASH"
                    },
                    {
                        "AttributeName": "done",
                        "KeyType": "RANGE"
                    }
                ],
                "Projection": {
                    "ProjectionType": "ALL"
                },
                "IndexStatus": "ACTIVE",
            }
        ],
    }
}
```

- slaffic_control_mention_settings
```json
{
    "Table": {
        "AttributeDefinitions": [
            {
                "AttributeName": "bot_id",
                "AttributeType": "S"
            }
        ],
        "TableName": "slaffic_control_mention_settings",
        "KeySchema": [
            {
                "AttributeName": "bot_id",
                "KeyType": "HASH"
            }
        ]
    }
}
```
