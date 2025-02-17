package model

import "time"

// メンション設定
type MentionSetting struct {
	ID        uint   `gorm:"primary_key"`
	Usernames string `gorm:"type:text"` // CSV "Uxxxxx,Syyyyy"
	CreatedAt time.Time
}
