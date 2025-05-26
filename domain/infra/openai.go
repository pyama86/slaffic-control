package infra

import (
	"context"
	"fmt"
	"os"

	"github.com/openai/openai-go"
	"github.com/openai/openai-go/azure"
	"github.com/openai/openai-go/option"
	"github.com/pyama86/slaffic-control/domain/model"
)

type OpenAI struct {
	client *openai.Client
}

func NewOpenAI() (*OpenAI, error) {
	if os.Getenv("OPENAI_API_KEY") == "" && os.Getenv("AZURE_OPENAI_KEY") == "" {
		return nil, nil
	}
	client, err := newOpenAIClient()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize OpenAI client: %w", err)
	}
	return &OpenAI{
		client: client,
	}, nil
}

func newOpenAIClient() (*openai.Client, error) {
	if os.Getenv("AZURE_OPENAI_ENDPOINT") != "" {
		return newAzureClient()
	}

	key := os.Getenv("OPENAI_API_KEY")
	if key == "" {
		return nil, fmt.Errorf("OPENAI_API_KEY is not set")
	}
	options := []option.RequestOption{
		option.WithAPIKey(os.Getenv("OPENAI_API_KEY")),
	}

	c := openai.NewClient(options...)
	return &c, nil
}

func newAzureClient() (*openai.Client, error) {
	key := os.Getenv("AZURE_OPENAI_KEY")
	if key == "" {
		return nil, fmt.Errorf("AZURE_OPENAI_KEY is not set")
	}
	var azureOpenAIEndpoint = os.Getenv("AZURE_OPENAI_ENDPOINT")

	var azureOpenAIAPIVersion = "2025-01-01-preview"

	if os.Getenv("AZURE_OPENAI_API_VERSION") != "" {
		azureOpenAIAPIVersion = os.Getenv("AZURE_OPENAI_API_VERSION")
	}

	c := openai.NewClient(
		azure.WithEndpoint(azureOpenAIEndpoint, azureOpenAIAPIVersion),
		azure.WithAPIKey(key),
	)
	return &c, nil
}

func (h *OpenAI) GenerateSummary(inquiries []model.InquiryConversation) (string, error) {
	prompt := fmt.Sprintf(`## 依頼内容
あなたに渡すコンテンツは私達のチームの直近の問い合わせと対応の履歴です。
内容は日付と、担当者と、問い合わせの内容と、Slackのスレッドのやりとりです。
チームで状況を把握するためのサマリを作ってください。

## 回答内容の指定
- 対応に時間がかかっている案件をピックアップする
  - 日本時間に変換したうえで、3日以上クローズされていない問い合わせを対象にしてください。
- 担当者の負担が高い状況であれば状況を説明する
- 一般的に対応が困難そうな内容であればその内容をピックアップする

## フォーマットの指定
*対応に時間がかかっている問い合わせ*
> {問い合わせの内容を羅列して、必要であればコメントしてください}

*担当者の負担が高い状況*
> {担当者の偏りがあれば、その内容を羅列して、必要であればコメントしてください}

*対応が困難そうな内容*
> {一般的に対応が困難そうな内容を羅列して、必要であればコメントしてください}

## 現在時刻
%s
## 問い合わせ内容
%s
`,
		timeNow().Format("2006-01-02 15:04:05"),
		inquiries,
	)

	response, err := h.client.Chat.Completions.New(context.TODO(), openai.ChatCompletionNewParams{
		Messages: []openai.ChatCompletionMessageParamUnion{
			openai.UserMessage(prompt),
		},
		Model: os.Getenv("OPENAI_MODEL"),
	})

	if err != nil {
		return "", fmt.Errorf("failed to call OpenAI API: %w", err)
	}

	return response.Choices[0].Message.Content, nil
}
