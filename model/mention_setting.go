package model

import "time"

// メンション設定
type MentionSetting struct {
	BotID     string `gorm:"type:varchar(50),primary_key"`
	Usernames string `gorm:"type:text"` // CSV "Uxxxxx,Syyyyy"
	CreatedAt time.Time
}
