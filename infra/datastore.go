package infra

import "github.com/pyama86/slaffic-control/model"

type Datastore interface {
	// 問い合わせを保存する
	SaveInquiry(*model.Inquiry) error
	// 未完了の最新の10件のInquiryを取得する
	GetLatestInquiries(string) ([]model.Inquiry, error)
	// 問い合わせを完了か未完了に更新する
	UpdateInquiryDone(string, string, bool) error

	// メンション設定を1件取得する
	GetMentionSetting(string) (*model.MentionSetting, error)
	// メンション設定を更新する
	UpdateMentionSetting(string, *model.MentionSetting) error
}
