package infra

import (
	"context"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/pyama86/slaffic-control/model"
)

type DynamoDB struct {
	db *dynamodb.Client
}

var tableNamePrefix = "slaffic_control"

func NewDynamoDB() (*DynamoDB, error) {
	if os.Getenv("DYNAMO_TABLE_NAME_PREFIX") != "" {
		tableNamePrefix = os.Getenv("DYNAMO_TABLE_NAME_PREFIX")
	}
	var db *dynamodb.Client
	if os.Getenv("DYNAMO_LOCAL") != "" {
		cfg, err := config.LoadDefaultConfig(context.TODO(),
			config.WithRegion("dummy"),
			config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider("dummy", "dummy", "dummy")),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration: %v", err)
		}

		db = dynamodb.NewFromConfig(cfg,
			func(o *dynamodb.Options) {
				o.BaseEndpoint = aws.String("http://localhost:8000")
			},
		)
	} else {
		cfg, err := config.LoadDefaultConfig(context.TODO())
		if err != nil {
			return nil, fmt.Errorf("failed to load configuration: %v", err)
		}

		db = dynamodb.NewFromConfig(cfg)
	}
	d := &DynamoDB{
		db: db,
	}
	if os.Getenv("DYNAMO_LOCAL") != "" {
		if err := d.EnsureTable(); err != nil {
			return nil, err
		}
	}
	return d, nil
}

func (d *DynamoDB) EnsureTable() error {
	tableName := tableNamePrefix + "_inquiries"

	_, err := d.db.DescribeTable(context.TODO(), &dynamodb.DescribeTableInput{
		TableName: aws.String(tableName),
	})
	if err == nil {
		return nil
	}

	_, err = d.db.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("bot_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("timestamp"),
				AttributeType: types.ScalarAttributeTypeS,
			},
			{
				AttributeName: aws.String("done"),
				AttributeType: types.ScalarAttributeTypeN,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("bot_id"),
				KeyType:       types.KeyTypeHash, // Partition Key
			},
			{
				AttributeName: aws.String("timestamp"),
				KeyType:       types.KeyTypeRange, // Sort Key
			},
		},
		GlobalSecondaryIndexes: []types.GlobalSecondaryIndex{
			{
				IndexName: aws.String("BotIdDoneIndex"),
				KeySchema: []types.KeySchemaElement{
					{
						AttributeName: aws.String("bot_id"),
						KeyType:       types.KeyTypeHash, // Partition Key
					},
					{
						AttributeName: aws.String("done"),
						KeyType:       types.KeyTypeRange, // Sort Key
					},
				},
				Projection: &types.Projection{
					ProjectionType: types.ProjectionTypeAll,
				},
				ProvisionedThroughput: &types.ProvisionedThroughput{
					ReadCapacityUnits:  aws.Int64(5),
					WriteCapacityUnits: aws.Int64(5),
				},
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create Inquiries table: %v", err)
	}

	tableName = tableNamePrefix + "_mention_settings"
	_, err = d.db.CreateTable(context.TODO(), &dynamodb.CreateTableInput{
		TableName: aws.String(tableName),
		AttributeDefinitions: []types.AttributeDefinition{
			{
				AttributeName: aws.String("bot_id"),
				AttributeType: types.ScalarAttributeTypeS,
			},
		},
		KeySchema: []types.KeySchemaElement{
			{
				AttributeName: aws.String("bot_id"),
				KeyType:       types.KeyTypeHash,
			},
		},
		ProvisionedThroughput: &types.ProvisionedThroughput{
			ReadCapacityUnits:  aws.Int64(5),
			WriteCapacityUnits: aws.Int64(5),
		},
	})
	if err != nil {
		return fmt.Errorf("failed to create MentionSettings table: %v", err)
	}

	return fmt.Errorf("table creation timeout")
}

func (d *DynamoDB) SaveInquiry(inquiry *model.Inquiry) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableNamePrefix + "_inquiries"),
		Item: map[string]types.AttributeValue{
			"bot_id":     &types.AttributeValueMemberS{Value: inquiry.BotID},
			"user_id":    &types.AttributeValueMemberS{Value: inquiry.UserID},
			"user_name":  &types.AttributeValueMemberS{Value: inquiry.UserName},
			"timestamp":  &types.AttributeValueMemberS{Value: inquiry.Timestamp},
			"channel_id": &types.AttributeValueMemberS{Value: inquiry.ChannelID},
			"done":       &types.AttributeValueMemberN{Value: "0"},
			"created_at": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
			"message":    &types.AttributeValueMemberS{Value: inquiry.Message},
		},
	}

	_, err := d.db.PutItem(context.TODO(), input)
	return err
}

func (d *DynamoDB) GetLatestInquiries(botID string) ([]model.Inquiry, error) {
	var inquiries []model.Inquiry

	input := &dynamodb.QueryInput{
		TableName:              aws.String(tableNamePrefix + "_inquiries"),
		KeyConditionExpression: aws.String("bot_id = :bot_id AND done = :done"),
		IndexName:              aws.String("BotIdDoneIndex"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":bot_id": &types.AttributeValueMemberS{Value: botID},
			":done":   &types.AttributeValueMemberN{Value: "0"},
		},
		ScanIndexForward: aws.Bool(false), // 降順（最新の created_at から取得）
		Limit:            aws.Int32(10),
	}

	result, err := d.db.Query(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	for _, item := range result.Items {
		createdAtStr := getStringValue(item, "created_at")
		createdAt, err := time.Parse(time.RFC3339, createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at (%s): %v", createdAtStr, err)
		}

		done, err := getNumberValue(item, "done")
		if err != nil {
			return nil, fmt.Errorf("failed to parse done: %v", err)
		}
		inquiry := model.Inquiry{
			Timestamp: getStringValue(item, "timestamp"),
			UserID:    getStringValue(item, "user_id"),
			UserName:  getStringValue(item, "user_name"),
			Message:   getStringValue(item, "message"),
			ChannelID: getStringValue(item, "channel_id"),
			CreatedAt: createdAt,
			Done:      done == 1,
		}
		inquiries = append(inquiries, inquiry)
	}

	return inquiries, nil
}

func getStringValue(item map[string]types.AttributeValue, key string) string {
	if v, ok := item[key].(*types.AttributeValueMemberS); ok {
		return v.Value
	}
	return ""
}

func getNumberValue(item map[string]types.AttributeValue, key string) (int, error) {
	if v, ok := item[key].(*types.AttributeValueMemberN); ok {
		return strconv.Atoi(v.Value)

	}
	return 0, fmt.Errorf("failed to parse %s", key)
}
func (d *DynamoDB) GetMentionSetting(id string) (*model.MentionSetting, error) {
	var setting model.MentionSetting
	input := &dynamodb.GetItemInput{
		TableName: aws.String(tableNamePrefix + "_mention_settings"),
		Key: map[string]types.AttributeValue{
			"bot_id": &types.AttributeValueMemberS{Value: id},
		},
	}

	result, err := d.db.GetItem(context.TODO(), input)
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return &setting, nil
	}

	setting.BotID = getStringValue(result.Item, "bot_id")
	setting.Usernames = getStringValue(result.Item, "user_names")
	// 他のフィールドを設定
	return &setting, nil
}

func (d *DynamoDB) UpdateMentionSetting(id string, setting *model.MentionSetting) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String(tableNamePrefix + "_mention_settings"),
		Item: map[string]types.AttributeValue{
			"bot_id":     &types.AttributeValueMemberS{Value: id},
			"user_names": &types.AttributeValueMemberS{Value: setting.Usernames},
			"created_at": &types.AttributeValueMemberS{Value: time.Now().Format(time.RFC3339)},
		},
	}

	_, err := d.db.PutItem(context.TODO(), input)
	return err
}

func (d *DynamoDB) UpdateInquiryDone(botID, timestamp string, done bool) error {
	doneValue := "0"
	if done {
		doneValue = "1"
	}
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String(tableNamePrefix + "_inquiries"),
		Key: map[string]types.AttributeValue{
			"bot_id":    &types.AttributeValueMemberS{Value: botID},
			"timestamp": &types.AttributeValueMemberS{Value: timestamp},
		},
		UpdateExpression: aws.String("SET done = :done"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":done": &types.AttributeValueMemberN{Value: doneValue},
		},
	}

	_, err := d.db.UpdateItem(context.TODO(), input)
	return err
}
