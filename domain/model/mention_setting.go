package model

import (
	"fmt"
	"strings"
	"time"
)

// メンション設定
type MentionSetting struct {
	BotID     string `gorm:"type:varchar(50),primary_key"`
	Usernames string `gorm:"type:text"` // CSV "Uxxxxx,Syyyyy"
	CreatedAt time.Time
}

func (m *MentionSetting) GetMentions() []string {
	names := strings.TrimSpace(m.Usernames)
	if names == "" {
		return nil
	}
	parts := strings.Split(names, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func (m *MentionSetting) GetCurrentMention() (string, error) {
	if m.BotID == "" || m.Usernames == "" {
		return "", nil
	}

	ids := m.GetMentions()
	if len(ids) == 0 {
		return "", nil
	}
	first := ids[0]
	if strings.HasPrefix(first, "S") {
		return fmt.Sprintf("<!subteam^%s>", first), nil // グループメンション
	} else if strings.HasPrefix(first, "U") {
		return fmt.Sprintf("<@%s>", first), nil // ユーザーメンション
	}
	return "", fmt.Errorf("invalid mention setting: %s", m.Usernames)
}
