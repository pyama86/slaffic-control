package infra

import (
	"time"

	"github.com/pyama86/slaffic-control/domain/model"
)

const showInquiriesLimit = 15

type Datastore interface {
	// 問い合わせを保存する
	SaveInquiry(*model.Inquiry) error
	// 未完了の最新の10件のInquiryを取得する
	GetLatestInquiries(string) ([]model.Inquiry, error)
	// 問い合わせを完了か未完了に更新する
	UpdateInquiryDone(string, string, bool) error
	// 問い合わせを検索する
	GetInquiry(string, string) (*model.Inquiry, error)
	// 過去一ヶ月の問い合わせを取得する
	GetMonthlyInquiries(string, time.Time) ([]model.Inquiry, error)

	// メンション設定を1件取得する
	GetMentionSetting(string) (*model.MentionSetting, error)
	// メンション設定を更新する
	UpdateMentionSetting(string, *model.MentionSetting) error
}

func timeNow() time.Time {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		loc = time.UTC
	}
	return time.Now().In(loc)
}
