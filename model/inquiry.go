package model

import "time"

type Inquiry struct {
	ID        uint   `gorm:"primary_key"`
	BotID     string `gorm:"type:varchar(50)"`
	Message   string `gorm:"type:text"`
	ChannelID string `gorm:"type:varchar(50)"`
	Timestamp string `gorm:"type:varchar(20)"`
	UserID    string `gorm:"type:varchar(50)"`  // 投稿者の Slack ユーザー ID
	UserName  string `gorm:"type:varchar(100)"` // 投稿者の名前
	Done      bool
	CreatedAt time.Time
}
