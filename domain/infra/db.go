package infra

import (
	"os"
	"path"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pyama86/slaffic-control/domain/model"
)

type DataBase struct {
	db *gorm.DB
}

func NewDataBase() (*DataBase, error) {
	dbpath := "./db/slaffic_control.db"
	if os.Getenv("DB_PATH") != "" {
		dbpath = os.Getenv("DB_PATH")
	}
	if !path.IsAbs(dbpath) {
		dbpath = path.Join(os.Getenv("PWD"), dbpath)
	}
	db, err := gorm.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}
	db.AutoMigrate(&model.Inquiry{})
	db.AutoMigrate(&model.MentionSetting{})
	return &DataBase{db: db}, nil
}

func (d *DataBase) SaveInquiry(inquiry *model.Inquiry) error {
	return d.db.Create(inquiry).Error
}

func (d *DataBase) GetMentionSetting(id string) (*model.MentionSetting, error) {
	var setting model.MentionSetting
	err := d.db.Where("bot_id = ?", id).First(&setting).Error
	if err == gorm.ErrRecordNotFound {
		return &setting, nil
	}
	return &setting, err
}

func (d *DataBase) UpdateMentionSetting(id string, setting *model.MentionSetting) error {
	setting.BotID = id
	return d.db.Save(setting).Error
}

func (d *DataBase) GetLatestInquiries(botID string) ([]model.Inquiry, error) {
	var inquiries []model.Inquiry
	err := d.db.Where("bot_id = ? AND done = ?", botID, false).Order("created_at desc").Limit(10).Find(&inquiries).Error
	return inquiries, err
}

func (d *DataBase) UpdateInquiryDone(botID, timestamp string, done bool) error {
	return d.db.Model(&model.Inquiry{}).Where("bot_id = ? AND timestamp = ?", botID, timestamp).Update("done", done).Error
}
