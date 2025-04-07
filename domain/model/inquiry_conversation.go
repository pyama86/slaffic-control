package model

import (
	"fmt"
	"time"
)

type Conversation struct {
	TimeStamp time.Time `json:"created_at"`
	Text      string    `json:"content"`
	User      string    `json:"user_name"`
}

type InquiryConversation struct {
	TimeStamp      string         `json:"created_at"`
	AssingneeName  string         `json:"assingnee_name"`
	InquiryContent string         `json:"inquiry_content"`
	Conversations  []Conversation `json:"conversations"`
}

func (c Conversation) String() string {
	return fmt.Sprintf("time:%s author:%s content:%s", c.TimeStamp, c.User, c.Text)
}

func (c InquiryConversation) String() string {
	return fmt.Sprintf("time:%s assignee:%s content:%s conversations:%v", c.TimeStamp, c.AssingneeName, c.InquiryContent, c.Conversations)
}
