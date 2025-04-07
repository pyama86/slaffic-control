package model

import "time"

type Inquiry struct {
	ID          uint   `gorm:"primary_key"`
	BotID       string `gorm:"type:varchar(50)"`
	Message     string `gorm:"type:text"`
	ChannelID   string `gorm:"type:varchar(50)"`
	Timestamp   string `gorm:"type:varchar(20)"`
	ThreadTS    string `gorm:"type:varchar(20)"`
	UserID      string `gorm:"type:varchar(50)"` // 投稿者の Slack ユーザー ID
	Mention     string `gorm:"type:varchar(50)"` // メンション先の Slack ユーザー ID(Deprecated)
	AssingneeID string `gorm:"type:varchar(50)"` // 担当者の Slack ユーザー ID
	Done        bool
	CreatedAt   time.Time
	DoneAt      time.Time
}
