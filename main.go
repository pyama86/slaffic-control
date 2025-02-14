package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
)

var (
	api            = slack.New(os.Getenv("SLACK_BOT_TOKEN"))
	signingSecret  = os.Getenv("SLACK_SIGNING_SECRET")
	db             *gorm.DB
	defaultChannel = os.Getenv("DEFAULT_CHANNEL") // 例: "#general"
)

type Inquiry struct {
	ID        uint   `gorm:"primary_key"`
	Message   string `gorm:"type:text"`
	ChannelID string `gorm:"type:varchar(50)"`
	Timestamp string `gorm:"type:varchar(20)"`
	UserID    string `gorm:"type:varchar(50)"`  // 投稿者の Slack ユーザー ID
	UserName  string `gorm:"type:varchar(100)"` // 投稿者の名前
	CreatedAt time.Time
}

// メンション設定
type MentionSetting struct {
	ID        uint   `gorm:"primary_key"`
	Usernames string `gorm:"type:text"` // CSV "Uxxxxx,Syyyyy"
	CreatedAt time.Time
}

func init() {
	var err error
	db, err = gorm.Open("sqlite3", "./taskbot.db")
	if err != nil {
		log.Fatal(err)
	}
	db.AutoMigrate(&Inquiry{}, &MentionSetting{})

	api = slack.New(os.Getenv("SLACK_BOT_TOKEN"))
	selfID = getBotUserID(api)
}

func main() {
	http.HandleFunc("/slack/events", handleSlackEvents)
	http.HandleFunc("/slack/interactions", handleInteractions)

	// 自動ローテーション
	startRotationMonitor()

	log.Println("[INFO] Server listening on :3000")
	http.ListenAndServe(":3000", nil)
}

// ---------------------------
// 1) イベントハンドラ
// ---------------------------
func handleSlackEvents(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Fail to read request body: %v", err)
		return
	}

	sv, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("[ERROR] Fail to verify SigningSecret: %v", err)
		return
	}
	if _, err := sv.Write(body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		log.Printf("[ERROR] Fail to write request body: %v", err)
		return
	}
	if err := sv.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("[ERROR] Fail to verify SigningSecret: %v", err)
		return
	}

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		log.Println(err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch eventsAPIEvent.Type {
	case slackevents.URLVerification:
		var res *slackevents.ChallengeResponse
		if err := json.Unmarshal(body, &res); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(res.Challenge)); err != nil {
			log.Println(err)
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	case slackevents.CallbackEvent:
		innerEvent := eventsAPIEvent.InnerEvent
		switch event := innerEvent.Data.(type) {
		case *slackevents.AppMentionEvent:
			handleMention(event)
		}
	}
}

var selfID string

// ボットのユーザーIDを取得する関数
func getBotUserID(api *slack.Client) string {
	authResp, err := api.AuthTest()
	if err != nil {
		log.Printf("[ERROR] Failed to get bot user ID: %v", err)
		return ""
	}
	return authResp.UserID
}

// メンションを受け取ったときの処理
func handleMention(event *slackevents.AppMentionEvent) {
	channelID := event.Channel
	userID := event.User

	// ボット自身のメンション (`@bot`) を削除
	messageText := strings.Replace(event.Text, fmt.Sprintf("<@%s>", selfID), "", 1)
	messageText = strings.TrimSpace(messageText) // 余計なスペースを削除

	// もしメンションにテキストが含まれていれば、問い合わせとして処理
	if messageText != "" {
		priority := "未設定"

		// Slack API から投稿者の情報を取得
		user, err := api.GetUserInfo(userID)
		if err != nil {
			log.Printf("[ERROR] GetUserInfo failed: %v", err)
		}

		// 投稿者の名前（表示名があれば優先）
		userName := user.Profile.DisplayName
		if userName == "" {
			userName = user.RealName
		}

		// 問い合わせをリッチメッセージで投稿
		timestamp, err := postInquiryRichMessage(channelID, priority, messageText)
		if err != nil {
			log.Printf("[ERROR] postInquiryRichMessage failed: %v", err)
			return
		}

		// 投稿者の情報も含めて問い合わせを保存
		saveInquiry(messageText, timestamp, userID, userName)

		// ユーザーに問い合わせとして受理したことを通知
		confirmationMsg := fmt.Sprintf(
			":white_check_mark: <@%s> さんの問い合わせを受け付けました。\n📝 内容: _%s_\n🔖 緊急度: *%s*",
			userID, messageText, priority,
		)

		_, _, err = api.PostMessage(
			channelID,
			slack.MsgOptionText(confirmationMsg, false),
		)
		if err != nil {
			log.Printf("[ERROR] Failed to send confirmation message: %s", err)
		}

		return
	}

	// ここまで来たら、通常のメニューを表示
	blocks := []slack.Block{
		newSectionBlock("section-1", "*メニューを選択してください*", "inquiry_action", "問い合わせを行う"),
		newSectionBlock("section-2", "*問い合わせの履歴を見る*", "history_action", "履歴を見る"),
		newSectionBlock("section-3", "*メンションの設定を行う*", "mention_action", "設定する"),
	}

	_, err := api.PostEphemeral(
		channelID,
		userID,
		slack.MsgOptionText("メンションされたので、選択肢を表示します。", false),
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		log.Printf("failed to post message with button: %s", err)
	}
}
func newSectionBlock(blockID, text, actionID, buttonText string) *slack.SectionBlock {
	return &slack.SectionBlock{
		Type:    slack.MBTSection,
		BlockID: blockID,
		Text: &slack.TextBlockObject{
			Type: slack.MarkdownType,
			Text: text,
		},
		Accessory: &slack.Accessory{
			ButtonElement: &slack.ButtonBlockElement{
				Type:     slack.METButton,
				ActionID: actionID,
				Value:    "dummy_value",
				Text: &slack.TextBlockObject{
					Type: "plain_text",
					Text: buttonText,
				},
			},
		},
	}
}

// ---------------------------
// 2) インタラクションハンドラ
// ---------------------------
func handleInteractions(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	sv, err := slack.NewSecretsVerifier(r.Header, signingSecret)
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("[ERROR] Failed to create secret verifier: %v", err)
		return
	}
	sv.Write(body)
	if err := sv.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		log.Printf("[ERROR] Failed to verify signature: %v", err)
		return
	}

	formData, _ := url.QueryUnescape(string(body))
	formData = strings.TrimPrefix(formData, "payload=")

	var callback slack.InteractionCallback
	if err := json.Unmarshal([]byte(formData), &callback); err != nil {
		log.Printf("[ERROR] Failed to unmarshal interaction: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch callback.Type {
	case slack.InteractionTypeBlockActions:
		if len(callback.ActionCallback.BlockActions) < 1 {
			w.WriteHeader(http.StatusOK)
			return
		}
		action := callback.ActionCallback.BlockActions[0]

		switch action.ActionID {
		case "inquiry_action":
			openInquiryModal(callback.TriggerID, callback.Channel.ID)
		case "history_action":
			showInquiries(callback.Channel.ID, callback.User.ID)
		case "mention_action":
			openMentionSettingModal(callback.TriggerID, callback.Channel.ID)
		}

	case slack.InteractionTypeViewSubmission:
		user, err := api.GetUserInfo(callback.User.ID)
		if err != nil {
			log.Printf("[ERROR] GetUserInfo failed: %v", err)
		}

		// 投稿者の名前（表示名があれば優先）
		userName := user.Profile.DisplayName
		if userName == "" {
			userName = user.RealName
		}

		switch callback.View.CallbackID {
		case "inquiry_modal":
			inputValue := callback.View.State.Values["inquiry_block"]["inquiry_text"].Value
			priority := callback.View.State.Values["priority_block"]["priority_select"].SelectedOption.Value
			channelID := callback.View.PrivateMetadata
			t, err := postInquiryRichMessage(channelID, priority, inputValue)
			if err != nil {
				log.Printf("[ERROR] postInquiryRichMessage failed: %v", err)
			}

			saveInquiry(inputValue, t, callback.User.ID, userName)

		case "mention_setting_modal":
			mentionsRaw := callback.View.State.Values["mention_block"]["mention_text"].Value
			channelID := callback.View.PrivateMetadata
			err := saveMentionSetting(mentionsRaw, channelID, userName)
			if err != nil {
				log.Printf("[ERROR] saveMentionSetting failed: %v", err)
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}

// ---------------------------
// 3) モーダル生成
// ---------------------------

func openInquiryModal(triggerID, channelID string) {
	titleText := slack.NewTextBlockObject("plain_text", "📩 問い合わせフォーム", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "✅ 送信", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "❌ キャンセル", false, false)

	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			// ヘッダー
			slack.NewHeaderBlock(
				slack.NewTextBlockObject("plain_text", "📩 問い合わせフォーム", false, false),
			),

			// 説明テキスト
			slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn", "*お問い合わせ内容を入力してください。*", false, false),
				nil, nil,
			),

			slack.NewDividerBlock(),

			// 緊急度選択
			&slack.InputBlock{
				Type:    slack.MBTInput,
				BlockID: "priority_block",
				Label: &slack.TextBlockObject{
					Type: "plain_text",
					Text: "🚨 緊急度",
				},
				Element: &slack.SelectBlockElement{
					Type:     slack.OptTypeStatic,
					ActionID: "priority_select",
					Options: []*slack.OptionBlockObject{
						slack.NewOptionBlockObject("normal",
							slack.NewTextBlockObject("plain_text", "低い", false, false), nil),
						slack.NewOptionBlockObject("high",
							slack.NewTextBlockObject("plain_text", "高い", false, false), nil),
						slack.NewOptionBlockObject("critical",
							slack.NewTextBlockObject("plain_text", "ウルトラ", false, false), nil),
					},
					Placeholder: slack.NewTextBlockObject("plain_text", "選択してください", false, false),
				},
			},

			slack.NewDividerBlock(),

			// 問い合わせ内容の入力欄
			&slack.InputBlock{
				Type:    slack.MBTInput,
				BlockID: "inquiry_block",
				Label: &slack.TextBlockObject{
					Type: "plain_text",
					Text: "📝 問い合わせ内容",
				},
				Element: &slack.PlainTextInputBlockElement{
					Type:      slack.METPlainTextInput,
					ActionID:  "inquiry_text",
					Multiline: true,
					Placeholder: slack.NewTextBlockObject(
						"plain_text", "内容を記入してください", false, false),
				},
			},

			slack.NewDividerBlock(),
		},
	}

	view := slack.ModalViewRequest{
		Type:            slack.ViewType("modal"),
		Title:           titleText,
		CallbackID:      "inquiry_modal",
		Submit:          submitText,
		Close:           closeText,
		Blocks:          blocks,
		PrivateMetadata: channelID,
	}

	if _, err := api.OpenView(triggerID, view); err != nil {
		log.Printf("[ERROR] failed to open inquiry modal: %s", err)
	}
}
func postInquiryRichMessage(channelID, priority, content string) (string, error) {
	var setting MentionSetting
	db.Last(&setting)
	first := "未設定"
	if setting.ID != 0 && setting.Usernames != "" {

		ids := parseCSV(setting.Usernames)
		if len(ids) == 0 {
			_, t, err := api.PostMessage(channelID, slack.MsgOptionText("*📩 新しい問い合わせが届きました*\n>>> "+content, false))
			if err != nil {
				return "", err
			}
			return t, nil
		}

		first = ids[0]
	}
	var mention string
	if strings.HasPrefix(first, "S") {
		mention = fmt.Sprintf("<!subteam^%s>", first) // グループメンション
	} else if strings.HasPrefix(first, "U") {
		mention = fmt.Sprintf("<@%s>", first) // ユーザーメンション
	}

	blocks := []slack.Block{
		// ヘッダー
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "📩 新しい問い合わせ", false, false),
		),
		slack.NewDividerBlock(),
		// 担当者情報
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*🔔 担当者:* %s", mention), false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
		// 問い合わせ内容
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "*📝 問い合わせ内容:*", false, false),
			nil, nil,
		),
		// 緊急度
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*🚨 緊急度:* %s", priority), false, false),
			nil, nil,
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf(">>> %s", content), false, false), // ボックス化
			nil, nil,
		),
		slack.NewDividerBlock(),
	}

	// 投稿
	_, t, err := api.PostMessage(channelID, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		return "", err
	}
	return t, nil
}

// 既存のメンション設定を取得
func getLatestMentionSetting() MentionSetting {
	var ms MentionSetting
	db.Last(&ms)
	return ms
}

// メンション設定モーダル
func openMentionSettingModal(triggerID, channelID string) {
	titleText := slack.NewTextBlockObject("plain_text", "メンション設定", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "保存", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "キャンセル", false, false)

	existing := getLatestMentionSetting()
	initialValue := reverseLookupMentionIDs(existing.Usernames)

	blocks := slack.Blocks{
		BlockSet: []slack.Block{
			&slack.InputBlock{
				Type:    slack.MBTInput,
				BlockID: "mention_block",
				Label: &slack.TextBlockObject{
					Type: "plain_text",
					Text: "メンションユーザ/グループ(カンマ区切り)",
				},
				Element: &slack.PlainTextInputBlockElement{
					Type:         slack.METPlainTextInput,
					ActionID:     "mention_text",
					Placeholder:  slack.NewTextBlockObject("plain_text", "@hoge,@dev-team", false, false),
					InitialValue: initialValue,
				},
			},
		},
	}

	view := slack.ModalViewRequest{
		Type:            slack.ViewType("modal"),
		CallbackID:      "mention_setting_modal",
		Title:           titleText,
		Submit:          submitText,
		Close:           closeText,
		Blocks:          blocks,
		PrivateMetadata: channelID,
	}

	if _, err := api.OpenView(triggerID, view); err != nil {
		log.Printf("[ERROR] failed to open mention setting modal: %s", err)
	}
}

// ---------------------------
// 4) 保存・投稿
// ---------------------------
func saveInquiry(message, timestamp, userID, userName string) {
	db.Create(&Inquiry{
		Message:   message,
		Timestamp: timestamp,
		UserID:    userID,
		UserName:  userName,
		CreatedAt: time.Now(),
	})
}

func saveMentionSetting(mentionsRaw, channelID, userName string) error {
	parsed := parseCSV(mentionsRaw)

	allUsers, err := api.GetUsers()
	if err != nil {
		return fmt.Errorf("GetUsers failed: %w", err)
	}
	allGroups, err := api.GetUserGroups()
	if err != nil {
		return fmt.Errorf("GetUserGroups failed: %w", err)
	}

	var results []string
	var mentionList []string
	for _, item := range parsed {
		nameOrGroup := strings.TrimPrefix(item, "@")
		nameOrGroup = strings.TrimSpace(nameOrGroup)
		if nameOrGroup == "" {
			continue
		}

		foundID := ""
		displayName := nameOrGroup

		// ユーザーを探す
		for _, u := range allUsers {
			if strings.EqualFold(u.Name, nameOrGroup) ||
				strings.EqualFold(u.Profile.DisplayName, nameOrGroup) ||
				strings.EqualFold(u.RealName, nameOrGroup) ||
				strings.EqualFold(u.Profile.RealName, nameOrGroup) {
				foundID = u.ID
				displayName = u.Profile.DisplayName
				if displayName == "" {
					displayName = u.RealName
				}
				break
			}
		}
		// 見つからなければグループ
		if foundID == "" {
			for _, grp := range allGroups {
				if strings.EqualFold(grp.Handle, nameOrGroup) ||
					strings.EqualFold(grp.Name, nameOrGroup) {
					foundID = grp.ID // "Sxxxx"
					displayName = grp.Name
					break
				}
			}
		}
		if foundID == "" {
			log.Printf("[WARN] '%s' not found", nameOrGroup)
			continue
		}
		results = append(results, foundID)
		mentionList = append(mentionList, fmt.Sprintf("%d. %s", len(mentionList)+1, displayName))

	}

	finalCSV := strings.Join(results, ",")
	db.Delete(&MentionSetting{}, "1=1")
	db.Create(&MentionSetting{
		Usernames: finalCSV,
		CreatedAt: time.Now(),
	})

	// 🔹 Block Kit メッセージ構築
	blocks := []slack.Block{
		// ヘッダー
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", fmt.Sprintf("📌 %sがメンション設定を保存しました！", userName), false, false),
		),
		slack.NewDividerBlock(),
		// 元の入力
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*📝 入力された値:* `%s`", mentionsRaw), false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
		// 変換結果
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "*🔗 保存されたメンション:*", false, false),
			nil, nil,
		),
	}

	// メンションリスト
	if len(mentionList) > 0 {
		for _, mention := range mentionList {
			blocks = append(blocks, slack.NewSectionBlock(
				slack.NewTextBlockObject("mrkdwn", mention, false, false),
				nil, nil,
			))
		}
	} else {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "⚠️ *有効なメンションはありませんでした*", false, false),
			nil, nil,
		))
	}

	// 送信
	api.PostMessage(channelID, slack.MsgOptionBlocks(blocks...))

	return nil
}

// IDs → @名前 の逆変換
func reverseLookupMentionIDs(csv string) string {
	if csv == "" {
		return ""
	}
	ids := parseCSV(csv)

	allUsers, err := api.GetUsers()
	if err != nil {
		log.Printf("[WARN] GetUsers failed: %v", err)
	}
	allGroups, err := api.GetUserGroups()
	if err != nil {
		log.Printf("[WARN] GetUserGroups failed: %v", err)
	}

	var result []string
	for _, id := range ids {
		if strings.HasPrefix(id, "U") {
			// ユーザー
			name := findUserNameByID(id, allUsers)
			if name != "" {
				result = append(result, "@"+name)
			} else {
				result = append(result, "@"+id)
			}
		} else if strings.HasPrefix(id, "S") {
			// グループ
			handle := findGroupHandleByID(id, allGroups)
			if handle != "" {
				result = append(result, "@"+handle)
			} else {
				result = append(result, "@"+id)
			}
		} else {
			result = append(result, "@"+id)
		}
	}
	return strings.Join(result, ",")
}

func findUserNameByID(userID string, allUsers []slack.User) string {
	for _, u := range allUsers {
		if u.ID == userID {
			return u.RealName // or u.Name
		}
	}
	return ""
}

func findGroupHandleByID(gid string, groups []slack.UserGroup) string {
	for _, g := range groups {
		if g.ID == gid {
			return g.Handle
		}
	}
	return ""
}

func showInquiries(channelID, userID string) {
	var inquiries []Inquiry
	db.Order("created_at desc").Limit(10).Find(&inquiries)

	if len(inquiries) == 0 {
		api.PostEphemeral(channelID, userID, slack.MsgOptionText("📭 *問い合わせ履歴はありません*", false))
		return
	}

	blocks := []slack.Block{
		// ヘッダー
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "📜 問い合わせ履歴", false, false),
		),
		slack.NewDividerBlock(),
	}

	// Slackのワークスペース名 (環境変数から取得)
	workspaceURL := os.Getenv("SLACK_WORKSPACE_URL")

	// 問い合わせ履歴をリスト化
	for _, i := range inquiries {
		t := i.CreatedAt.Format("2006-01-02 15:04:05")

		// SlackメッセージURLの生成
		slackURL := fmt.Sprintf("%s/archives/%s/p%s", workspaceURL, channelID, i.Timestamp)

		// 投稿者名の取得（メンションが飛ばないように）
		postedBy := "不明"
		if i.UserName != "" {
			postedBy = i.UserName // メンションを飛ばさないため、単純な文字列
		}

		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn",
				fmt.Sprintf("👤 *投稿者:* %s\n📅 *%s*\n📝 [%d] %s\n📎 <%s|詳細を見る>",
					postedBy, t, i.ID, i.Message, slackURL),
				false, false),
			nil, nil,
		))
		blocks = append(blocks, slack.NewDividerBlock())
	}

	// コンテキスト（履歴の上限について）
	blocks = append(blocks, slack.NewContextBlock("",
		slack.NewTextBlockObject("mrkdwn",
			"📌 *最新 10 件の履歴を表示しています*",
			false, false),
	))

	api.PostEphemeral(channelID, userID, slack.MsgOptionBlocks(blocks...))
}

// ---------------------------
// 5) ユーティリティ
// ---------------------------
func parseCSV(csv string) []string {
	csv = strings.TrimSpace(csv)
	if csv == "" {
		return nil
	}
	parts := strings.Split(csv, ",")
	var result []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

// ---------------------------
// 6) ローテーション
// ---------------------------

// startRotationMonitor: 日本時間の朝9時にローテーション
func startRotationMonitor() {
	dayStr := os.Getenv("ROTATION_DAY") // 0=日,1=月,...,6=土
	if dayStr == "" {
		dayStr = "1" // デフォルトは月曜日
	}
	desiredDay, err := strconv.Atoi(dayStr)
	if err != nil || desiredDay < 0 || desiredDay > 6 {
		log.Printf("[WARN] invalid ROTATION_DAY='%s', skip rotation", dayStr)
		return
	}

	go func() {
		loc, _ := time.LoadLocation("Asia/Tokyo") // 日本時間
		for {
			now := time.Now().In(loc)
			nextRotation := time.Date(now.Year(), now.Month(), now.Day(), 9, 0, 0, 0, loc)

			// すでに9時を過ぎていたら翌日
			if now.After(nextRotation) {
				nextRotation = nextRotation.Add(24 * time.Hour)
			}

			// 次の9時までの時間を計算してスリープ
			sleepDuration := time.Until(nextRotation)
			log.Printf("[INFO] 次のローテーションは %s に実行 (%.0f 秒後)", nextRotation, sleepDuration.Seconds())
			time.Sleep(sleepDuration)

			// 今日が指定された曜日ならローテーションを実行
			now = time.Now().In(loc) // スリープ後に再取得
			if int(now.Weekday()) == desiredDay {
				log.Println("[INFO] ローテーションを実行します")
				rotateMentions()
			}
		}
	}()
}

func rotateMentions() {
	if defaultChannel == "" {
		log.Println("[WARN] DEFAULT_CHANNEL is not set, skip rotation message.")
		return
	}

	var setting MentionSetting
	db.Last(&setting)
	if setting.ID == 0 || setting.Usernames == "" {
		log.Println("[INFO] No mention setting found, skip rotation.")
		return
	}

	ids := parseCSV(setting.Usernames)
	if len(ids) < 2 {
		log.Println("[INFO] Only one or none in mention setting, skip rotation.")
		return
	}

	// 先頭を末尾へ
	first := ids[0]
	rotated := append(ids[1:], first)
	first = rotated[0]
	newCSV := strings.Join(rotated, ",")
	setting.Usernames = newCSV
	db.Save(&setting)

	// メンション文字列
	var mentionStr string
	if strings.HasPrefix(first, "U") {
		mentionStr = fmt.Sprintf("<@%s>", first) // user mention
	} else if strings.HasPrefix(first, "S") {
		mentionStr = fmt.Sprintf("<!subteam^%s>", first) // group mention
	}

	// 全員のハンドルネームを取得
	allMentions := []string{}
	for _, id := range rotated {
		allMentions = append(allMentions, lookupRealNameOrHandle(id))
	}

	// 🎨 Block Kit メッセージ構築
	blocks := []slack.Block{
		// ヘッダー (太字 + 絵文字)
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "🌀 担当ローテーション", false, false),
		),
		// 色付きのアイコン（疑似的な強調）
		slack.NewContextBlock("",
			slack.NewTextBlockObject("mrkdwn", ":large_blue_circle: *担当が変わりました！*", false, false),
		),
		slack.NewDividerBlock(),
		// 新しい担当
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*新しい担当者:* %s 🎯", mentionStr), false, false),
			nil, nil,
		),
		slack.NewDividerBlock(),
		// 担当リスト
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "*📋 新しい担当順:*", false, false),
			nil, nil,
		),
	}

	// 順番リスト（番号付き）
	for i, mention := range allMentions {
		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*%d.* %s", i+1, mention), false, false),
			nil, nil,
		))
	}

	// 送信
	api.PostMessage(
		defaultChannel,
		slack.MsgOptionBlocks(blocks...),
	)

	log.Printf("[INFO] mention setting rotated: %s", newCSV)
}

// lookupRealNameOrHandle: "Uxxxx" or "Sxxxx" をユーザー/グループ名に変換
func lookupRealNameOrHandle(id string) string {
	fmt.Printf("lookupRealNameOrHandle: %s\n", id)
	if strings.HasPrefix(id, "U") {
		// user
		u, err := api.GetUserInfo(id)

		if err != nil {
			return id
		}
		return u.RealName
	} else if strings.HasPrefix(id, "S") {
		groups, err := api.GetUserGroups()
		if err != nil {
			return id
		}
		for _, g := range groups {
			if g.ID == id {
				return g.Handle
			}
		}
	}
	return id
}
