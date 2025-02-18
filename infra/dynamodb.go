package infra

import (
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/credentials"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/dynamodb"
	"github.com/aws/aws-sdk-go/service/dynamodb/dynamodbiface"
	"github.com/pyama86/slaffic-control/model"
)

type DynamoDB struct {
	db dynamodbiface.DynamoDBAPI
}

func NewDynamoDB() (*DynamoDB, error) {
	region := os.Getenv("AWS_REGION")
	if region == "" {
		region = "ap-northeast-1"
	}

	var db dynamodbiface.DynamoDBAPI
	if os.Getenv("DYNAMO_LOCAL") != "" {
		slog.Info("use local dynamodb")
		db = dynamodb.New(session.Must(session.NewSession(&aws.Config{
			CredentialsChainVerboseErrors: aws.Bool(true),
			Region:                        aws.String(region),
			Endpoint:                      aws.String("http://localhost:8000"),
			Credentials:                   credentials.NewStaticCredentials("dummy", "dummy", "dummy"),
		})))
	} else {
		slog.Info("use aws dynamodb")
		db = dynamodb.New(session.Must(session.NewSession(&aws.Config{
			Region: aws.String(region),
		})))
	}

	database := &DynamoDB{db: db}
	if err := database.ensureTable(); err != nil {
		return nil, fmt.Errorf("failed to ensure table: %v", err)
	}
	return database, nil
}

func (d *DynamoDB) ensureTable() error {
	_, err := d.db.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String("Inquiries"),
	})
	if err != nil {
		_, err := d.db.CreateTable(&dynamodb.CreateTableInput{
			TableName: aws.String("Inquiries"),
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("bot_id"),
					AttributeType: aws.String("S"),
				},
				{
					AttributeName: aws.String("timestamp"),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("bot_id"),
					KeyType:       aws.String("HASH"),
				},
				{
					AttributeName: aws.String("timestamp"),
					KeyType:       aws.String("RANGE"),
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create Inquiries table: %v", err)
		}
	}

	_, err = d.db.DescribeTable(&dynamodb.DescribeTableInput{
		TableName: aws.String("MentionSettings"),
	})
	if err != nil {
		_, err := d.db.CreateTable(&dynamodb.CreateTableInput{
			TableName: aws.String("MentionSettings"),
			AttributeDefinitions: []*dynamodb.AttributeDefinition{
				{
					AttributeName: aws.String("bot_id"),
					AttributeType: aws.String("S"),
				},
			},
			KeySchema: []*dynamodb.KeySchemaElement{
				{
					AttributeName: aws.String("bot_id"),
					KeyType:       aws.String("HASH"),
				},
			},
			ProvisionedThroughput: &dynamodb.ProvisionedThroughput{
				ReadCapacityUnits:  aws.Int64(5),
				WriteCapacityUnits: aws.Int64(5),
			},
		})
		if err != nil {
			return fmt.Errorf("failed to create MentionSettings table: %v", err)
		}
	}

	return nil
}

func (d *DynamoDB) SaveInquiry(inquiry *model.Inquiry) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String("Inquiries"),
		Item: map[string]*dynamodb.AttributeValue{
			"bot_id":     {S: aws.String(inquiry.BotID)},
			"user_id":    {S: aws.String(inquiry.UserID)},
			"user_name":  {S: aws.String(inquiry.UserName)},
			"timestamp":  {S: aws.String(inquiry.Timestamp)},
			"channel_id": {S: aws.String(inquiry.ChannelID)},
			"done":       {BOOL: aws.Bool(inquiry.Done)},
			"created_at": {S: aws.String(time.Now().String())},
			"message":    {S: aws.String(inquiry.Message)},
		},
	}

	_, err := d.db.PutItem(input)
	return err
}

func (d *DynamoDB) GetLatestInquiries(botID string) ([]model.Inquiry, error) {
	var inquiries []model.Inquiry

	input := &dynamodb.QueryInput{
		TableName:              aws.String("Inquiries"),
		KeyConditionExpression: aws.String("bot_id = :bot_id"),
		FilterExpression:       aws.String("done = :done"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":bot_id": {S: aws.String(botID)},
			":done":   {BOOL: aws.Bool(false)},
		},
		ScanIndexForward: aws.Bool(false), // 降順（最新の created_at から取得）
		Limit:            aws.Int64(10),
	}

	result, err := d.db.Query(input)
	if err != nil {
		return nil, err
	}

	for _, item := range result.Items {
		createdAtStr := *item["created_at"].S
		createdAtStr = strings.Split(createdAtStr, " m=")[0]

		layout := "2006-01-02 15:04:05.999999 -0700 MST"
		createdAt, err := time.Parse(layout, createdAtStr)
		if err != nil {
			return nil, fmt.Errorf("failed to parse created_at (%s): %v", createdAtStr, err)
		}

		inquiry := model.Inquiry{
			Timestamp: *item["timestamp"].S,
			UserID:    *item["user_id"].S,
			UserName:  *item["user_name"].S,
			Message:   *item["message"].S,
			ChannelID: *item["channel_id"].S,
			CreatedAt: createdAt,
			Done:      *item["done"].BOOL,
		}
		inquiries = append(inquiries, inquiry)
	}

	return inquiries, nil
}
func (d *DynamoDB) GetMentionSetting(id string) (*model.MentionSetting, error) {
	var setting model.MentionSetting
	input := &dynamodb.GetItemInput{
		TableName: aws.String("MentionSettings"),
		Key: map[string]*dynamodb.AttributeValue{
			"bot_id": {S: aws.String(id)},
		},
	}

	result, err := d.db.GetItem(input)
	if err != nil {
		return nil, err
	}

	if result.Item == nil {
		return &setting, nil
	}

	setting.BotID = *result.Item["bot_id"].S
	setting.Usernames = *result.Item["user_names"].S
	// 他のフィールドを設定
	return &setting, nil
}

func (d *DynamoDB) UpdateMentionSetting(id string, setting *model.MentionSetting) error {
	input := &dynamodb.PutItemInput{
		TableName: aws.String("MentionSettings"),
		Item: map[string]*dynamodb.AttributeValue{
			"bot_id":     {S: aws.String(id)},
			"user_names": {S: aws.String(setting.Usernames)},
			"created_at": {S: aws.String(time.Now().String())},
		},
	}

	_, err := d.db.PutItem(input)
	return err
}

func (d *DynamoDB) UpdateInquiryDone(botID, timestamp string, done bool) error {
	input := &dynamodb.UpdateItemInput{
		TableName: aws.String("Inquiries"),
		Key: map[string]*dynamodb.AttributeValue{
			"bot_id":    {S: aws.String(botID)},
			"timestamp": {S: aws.String(timestamp)},
		},
		UpdateExpression: aws.String("SET done = :done"),
		ExpressionAttributeValues: map[string]*dynamodb.AttributeValue{
			":done": {BOOL: aws.Bool(done)},
		},
	}

	_, err := d.db.UpdateItem(input)
	return err
}
