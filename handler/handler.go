package handler

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	"github.com/jinzhu/gorm"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pyama86/slaffic-control/model"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
)

var defaultChannel = os.Getenv("DEFAULT_CHANNEL")

type SlackAPI interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
	OpenView(triggerID string, view slack.ModalViewRequest) (*slack.ViewResponse, error)
	AuthTest() (*slack.AuthTestResponse, error)
	GetUsers(options ...slack.GetUsersOption) ([]slack.User, error)
	GetUserGroups(options ...slack.GetUserGroupsOption) ([]slack.UserGroup, error)
	GetUserInfo(userID string) (*slack.User, error)
	PostEphemeral(channelID, userID string, options ...slack.MsgOption) (string, error)
}

type Handler struct {
	client        SlackAPI
	userCache     *ttlcache.Cache[string, []slack.User]
	groupCache    *ttlcache.Cache[string, []slack.UserGroup]
	userInfoCache *ttlcache.Cache[string, *slack.User]
	db            *gorm.DB
	botID         string
}

func NewHandler() (*Handler, error) {
	dbpath := "./db/slaffic_control.db"
	if os.Getenv("DB_PATH") != "" {
		dbpath = os.Getenv("DB_PATH")
	}
	if !path.IsAbs(dbpath) {
		dbpath = path.Join(os.Getenv("PWD"), dbpath)
	}
	fmt.Println("dbpath", dbpath)

	db, err := gorm.Open("sqlite3", dbpath)
	if err != nil {
		return nil, err
	}
	if err := db.AutoMigrate(&model.Inquiry{}, &model.MentionSetting{}).Error; err != nil {
		return nil, err
	}

	api := slack.New(os.Getenv("SLACK_BOT_TOKEN"))
	return &Handler{
		client:        api,
		userCache:     ttlcache.New[string, []slack.User](ttlcache.WithTTL[string, []slack.User](time.Hour)),
		groupCache:    ttlcache.New[string, []slack.UserGroup](ttlcache.WithTTL[string, []slack.UserGroup](time.Hour)),
		userInfoCache: ttlcache.New[string, *slack.User](ttlcache.WithTTL[string, *slack.User](24 * time.Hour)),
		db:            db,
	}, nil
}
func (h *Handler) openInquiryModal(triggerID, channelID string) error {
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
						slack.NewOptionBlockObject("低い",
							slack.NewTextBlockObject("plain_text", "低い", false, false), nil),
						slack.NewOptionBlockObject("高い",
							slack.NewTextBlockObject("plain_text", "高い", false, false), nil),
						slack.NewOptionBlockObject("ウルトラ",
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

	_, err := h.client.OpenView(triggerID, view)
	return err
}
func (h *Handler) postInquiryRichMessage(channelID, priority, content string) (string, error) {
	var setting model.MentionSetting
	if err := h.db.Last(&setting).Error; err != nil {
		return "", err
	}
	first := "未設定"
	if setting.ID != 0 && setting.Usernames != "" {

		ids := parseCSV(setting.Usernames)
		if len(ids) == 0 {
			_, t, err := h.client.PostMessage(channelID, slack.MsgOptionText("*📩 新しい問い合わせが届きました*\n>>> "+content, false))
			if err != nil {
				return "", err
			}
			return t, nil
		}

		first = ids[0]
	}
	mention := "未設定"
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
		// white_check_markリアクションについての説明
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "✅のリアクションを付けると、この問い合わせは履歴から表示されなくなります。", false, false),
			nil, nil,
		),
	}

	// 投稿
	_, t, err := h.client.PostMessage(channelID, slack.MsgOptionBlocks(blocks...))
	if err != nil {
		return "", err
	}
	return t, nil
}

func (h *Handler) getLatestMentionSetting() (model.MentionSetting, error) {
	var ms model.MentionSetting
	if err := h.db.Last(&ms).Error; err != nil {
		return ms, err
	}

	return ms, nil
}

func (h *Handler) openMentionSettingModal(triggerID, channelID string) error {
	titleText := slack.NewTextBlockObject("plain_text", "メンション設定", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "保存", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "キャンセル", false, false)

	existing, err := h.getLatestMentionSetting()
	if err != nil {
		return err
	}

	initialValue, err := h.reverseLookupMentionIDs(existing.Usernames)
	if err != nil {
		return err
	}

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

	_, err = h.client.OpenView(triggerID, view)
	return err
}

func (h *Handler) saveInquiry(message, timestamp, channelID, userID, userName string) error {
	return h.db.Create(&model.Inquiry{
		Message:   message,
		Timestamp: timestamp,
		ChannelID: channelID,
		UserID:    userID,
		UserName:  userName,
		CreatedAt: time.Now(),
	}).Error
}

func (h *Handler) getUsers() ([]slack.User, error) {
	cacheKey := "users"
	if users := h.userCache.Get(cacheKey); users != nil {
		return users.Value(), nil
	}
	users, err := h.client.GetUsers()
	if err != nil {
		return nil, err
	}
	h.userCache.Set(cacheKey, users, ttlcache.DefaultTTL)
	return users, nil
}

func (h *Handler) getUserGroups() ([]slack.UserGroup, error) {
	cacheKey := "user_groups"
	if groups := h.groupCache.Get(cacheKey); groups != nil {
		return groups.Value(), nil
	}
	groups, err := h.client.GetUserGroups()
	if err != nil {
		return nil, err
	}
	h.groupCache.Set(cacheKey, groups, ttlcache.DefaultTTL)
	return groups, nil
}

func (h *Handler) getUserInfo(userID string) (*slack.User, error) {
	cacheKey := "user_" + userID
	if user := h.userInfoCache.Get(cacheKey); user != nil {
		return user.Value(), nil
	}
	user, err := h.client.GetUserInfo(userID)
	if err != nil {
		return nil, err
	}
	h.userInfoCache.Set(cacheKey, user, ttlcache.DefaultTTL)
	return user, nil
}

// @名前 → ID の変換
func (h *Handler) findUserOrGroupIDAndDisplayNameByName(name string) (string, string, error) {
	users, err := h.getUsers()
	if err != nil {
		return "", "", err
	}
	groups, err := h.getUserGroups()
	if err != nil {
		return "", "", err
	}

	for _, u := range users {
		if strings.EqualFold(u.Name, name) ||
			strings.EqualFold(u.Profile.DisplayName, name) ||
			strings.EqualFold(u.RealName, name) ||
			strings.EqualFold(u.Profile.RealName, name) {
			if u.Profile.DisplayName == "" {
				return u.ID, u.RealName, nil
			}
			return u.ID, u.Profile.DisplayName, nil
		}
	}
	for _, g := range groups {
		if strings.EqualFold(g.Handle, name) ||
			strings.EqualFold(g.Name, name) {
			return g.ID, g.Name, nil
		}
	}
	return "", "", fmt.Errorf("user or group not found")
}

func (h *Handler) saveMentionSetting(mentionsRaw, channelID, userName string) error {
	parsed := parseCSV(mentionsRaw)
	var results []string
	var mentionList []string
	for _, item := range parsed {
		nameOrGroup := strings.TrimPrefix(item, "@")
		nameOrGroup = strings.TrimSpace(nameOrGroup)
		if nameOrGroup == "" {
			continue
		}

		foundID, displayName, err := h.findUserOrGroupIDAndDisplayNameByName(nameOrGroup)
		if err != nil {
			return fmt.Errorf("findUserOrGroupIDAndDisplayNameByName failed: %w", err)
		}

		if foundID == "" {
			return fmt.Errorf("user or group not found: %s", nameOrGroup)
		}
		results = append(results, foundID)
		mentionList = append(mentionList, fmt.Sprintf("%d. %s", len(mentionList)+1, displayName))
	}

	finalCSV := strings.Join(results, ",")
	if err := h.db.Delete(&model.MentionSetting{}, "1=1").Error; err != nil {
		return fmt.Errorf("Delete failed: %w", err)
	}
	if err := h.db.Create(&model.MentionSetting{
		Usernames: finalCSV,
		CreatedAt: time.Now(),
	}).Error; err != nil {
		return fmt.Errorf("Create failed: %w", err)
	}

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
	if _, _, err := h.client.PostMessage(channelID, slack.MsgOptionBlocks(blocks...)); err != nil {
		return fmt.Errorf("PostMessage failed: %w", err)
	}

	return nil
}

// IDs → @名前 の逆変換
func (h *Handler) reverseLookupMentionIDs(csv string) (string, error) {
	if csv == "" {
		return "", nil
	}
	ids := parseCSV(csv)

	allUsers, err := h.getUsers()
	if err != nil {
		return "", fmt.Errorf("GetUsers failed: %w", err)
	}
	allGroups, err := h.getUserGroups()
	if err != nil {
		return "", fmt.Errorf("GetUserGroups failed: %w", err)
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
	return strings.Join(result, ","), nil
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

func (h *Handler) showInquiries(channelID, userID string) error {
	var inquiries []model.Inquiry
	if h.db.Where("done = ?", false).Order("created_at desc").Limit(10).Find(&inquiries).Error != nil {
		if _, err := h.client.PostEphemeral(channelID, userID, slack.MsgOptionText("📭 *問い合わせ履歴の取得に失敗しました*", false)); err != nil {
			return err
		}
	}

	if len(inquiries) == 0 {
		if _, err := h.client.PostEphemeral(channelID, userID, slack.MsgOptionText("📭 *問い合わせ履歴はありません*", false)); err != nil {
			return err
		}
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

	_, err := h.client.PostEphemeral(channelID, userID, slack.MsgOptionBlocks(blocks...))
	return err
}

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

// startRotationMonitor: 日本時間の朝9時にローテーション
func (h *Handler) StartRotationMonitor() {
	dayStr := os.Getenv("ROTATION_DAY") // 0=日,1=月,...,6=土
	if dayStr == "" {
		dayStr = "1" // デフォルトは月曜日
	}
	desiredDay, err := strconv.Atoi(dayStr)
	if err != nil || desiredDay < 0 || desiredDay > 6 {
		slog.Error("Invalid ROTATION_DAY", slog.Any("day", dayStr))
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
			slog.Info("Next rotation", slog.Any("next", nextRotation), slog.Any("sleep", sleepDuration))
			time.Sleep(sleepDuration)

			// 今日が指定された曜日ならローテーションを実行
			now = time.Now().In(loc) // スリープ後に再取得
			if int(now.Weekday()) == desiredDay {
				slog.Info("Rotation time has come, start rotation")
				h.rotateMentions()
			}
		}
	}()
}

func (h *Handler) rotateMentions() {

	var setting model.MentionSetting
	if err := h.db.Last(&setting).Error; err != nil {
		slog.Error("Failed to get latest mention setting", slog.Any("err", err))
	}

	if setting.ID == 0 || setting.Usernames == "" {
		slog.Info("No mention setting found, skip rotation")
		return
	}

	ids := parseCSV(setting.Usernames)
	if len(ids) < 2 {
		slog.Info("Not enough users/groups for rotation", slog.Any("count", len(ids)))
		return
	}

	// 先頭を末尾へ
	first := ids[0]
	rotated := append(ids[1:], first)
	first = rotated[0]
	newCSV := strings.Join(rotated, ",")
	setting.Usernames = newCSV
	if err := h.db.Save(&setting).Error; err != nil {
		slog.Error("Failed to save new mention setting", slog.Any("err", err))
		return
	}

	if defaultChannel == "" {
		slog.Warn("No default channel set for rotation")
		return
	}

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
		allMentions = append(allMentions, h.lookupRealNameOrHandle(id))
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
	if _, _, err := h.client.PostMessage(
		defaultChannel,
		slack.MsgOptionBlocks(blocks...),
	); err != nil {
		slog.Error("Failed to post rotation message", slog.Any("err", err))
	}
	slog.Info("Rotation completed", slog.Any("new", first), slog.Any("all", allMentions))

}

// lookupRealNameOrHandle: "Uxxxx" or "Sxxxx" をユーザー/グループ名に変換
func (h *Handler) lookupRealNameOrHandle(id string) string {
	if strings.HasPrefix(id, "U") {
		// user
		u, err := h.getUserInfo(id)

		if err != nil {
			return id
		}
		return u.RealName
	} else if strings.HasPrefix(id, "S") {
		groups, err := h.getUserGroups()
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

func (h *Handler) getBotUserID() string {
	if h.botID != "" {
		authResp, err := h.client.AuthTest()
		if err != nil {
			slog.Error("Failed to get bot user ID", slog.Any("err", err))
			return ""
		}
		h.botID = authResp.UserID
	}
	return h.botID
}

func (h *Handler) HandleSlackEvents(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	body, err := io.ReadAll(r.Body)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("Failed to read request body", slog.Any("err", err))
		return
	}

	sv, err := slack.NewSecretsVerifier(r.Header, os.Getenv("SLACK_SIGNING_SECRET"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		slog.Error("Failed to create secret verifier", slog.Any("err", err))
		return
	}
	if _, err := sv.Write(body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("Failed to write request body", slog.Any("err", err))
		return
	}
	if err := sv.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		slog.Error("Failed to verify signature", slog.Any("err", err))
		return
	}

	eventsAPIEvent, err := slackevents.ParseEvent(json.RawMessage(body), slackevents.OptionNoVerifyToken())
	if err != nil {
		slog.Error("Failed to parse event", slog.Any("err", err))
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	switch eventsAPIEvent.Type {
	case slackevents.URLVerification:
		var res *slackevents.ChallengeResponse
		if err := json.Unmarshal(body, &res); err != nil {
			slog.Error("Failed to unmarshal challenge response", slog.Any("err", err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		if _, err := w.Write([]byte(res.Challenge)); err != nil {
			slog.Error("Failed to write challenge response", slog.Any("err", err))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

	case slackevents.CallbackEvent:
		innerEvent := eventsAPIEvent.InnerEvent
		slog.Info("Event received", slog.Any("event", innerEvent))
		switch event := innerEvent.Data.(type) {
		case *slackevents.AppMentionEvent:
			h.handleMention(event)
		case *slackevents.ReactionAddedEvent:
			if event.Reaction == "white_check_mark" {
				err := h.db.Table("inquiries").Where("timestamp = ? AND channel_id = ?", event.Item.Timestamp, event.Item.Channel).Update("done", true).Error
				if err != nil {
					slog.Error("Failed to update inquiry", slog.Any("err", err))
				} else {
					slog.Info("Inquiry done", slog.String("timestamp", event.Item.Timestamp))
				}
			}
		case *slackevents.ReactionRemovedEvent:
			if event.Reaction == "white_check_mark" {
				err := h.db.Table("inquiries").Where("timestamp = ? AND channel_id = ?", event.Item.Timestamp, event.Item.Channel).Update("done", false).Error
				if err != nil {
					slog.Error("Failed to restore inquiry", slog.Any("err", err))
				} else {
					slog.Info("Inquiry restored", slog.String("timestamp", event.Item.Timestamp))
				}
			}
		}
	}
}

// メンションを受け取ったときの処理
func (h *Handler) handleMention(event *slackevents.AppMentionEvent) {
	channelID := event.Channel
	userID := event.User

	// ボット自身のメンション (`@bot`) を削除
	messageText := strings.Replace(event.Text, fmt.Sprintf("<@%s>", h.getBotUserID()), "", 1)
	messageText = strings.TrimSpace(messageText) // 余計なスペースを削除

	// もしメンションにテキストが含まれていれば、問い合わせとして処理
	if messageText != "" {
		priority := "未設定"

		// Slack API から投稿者の情報を取得
		user, err := h.getUserInfo(userID)
		if err != nil {
			slog.Error("GetUserInfo failed", slog.Any("err", err))
			return
		}

		// 投稿者の名前（表示名があれば優先）
		userName := user.Profile.DisplayName
		if userName == "" {
			userName = user.RealName
		}

		// 問い合わせをリッチメッセージで投稿
		timestamp, err := h.postInquiryRichMessage(channelID, priority, messageText)
		if err != nil {
			slog.Error("postInquiryRichMessage failed", slog.Any("err", err))
			return
		}

		// 投稿者の情報も含めて問い合わせを保存
		if err := h.saveInquiry(messageText, timestamp, channelID, userID, userName); err != nil {
			slog.Error("saveInquiry failed", slog.Any("err", err))
			return
		}
		return
	}

	// ここまで来たら、通常のメニューを表示
	blocks := []slack.Block{
		newSectionBlock("section-1", "*メニューを選択してください*", "inquiry_action", "問い合わせを行う"),
		newSectionBlock("section-2", "*問い合わせの履歴を見る*", "history_action", "履歴を見る"),
		newSectionBlock("section-3", "*メンションの設定を行う*", "mention_action", "設定する"),
	}

	_, err := h.client.PostEphemeral(
		channelID,
		userID,
		slack.MsgOptionText("メンションされたので、選択肢を表示します。", false),
		slack.MsgOptionBlocks(blocks...),
	)
	if err != nil {
		slog.Error("Failed to post message with button", slog.Any("err", err))
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

func (h *Handler) HandleInteractions(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	r.Body.Close()

	sv, err := slack.NewSecretsVerifier(r.Header, os.Getenv("SLACK_SIGNING_SECRET"))
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		slog.Error("Failed to create secret verifier", slog.Any("err", err))
		return
	}
	if _, err := sv.Write(body); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		slog.Error("Failed to write request body", slog.Any("err", err))
		return
	}
	if err := sv.Ensure(); err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		slog.Error("Failed to verify signature", slog.Any("err", err))
		return
	}

	formData, _ := url.QueryUnescape(string(body))
	formData = strings.TrimPrefix(formData, "payload=")

	var callback slack.InteractionCallback
	if err := json.Unmarshal([]byte(formData), &callback); err != nil {
		slog.Error("Failed to unmarshal interaction", slog.Any("err", err))
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
			if err := h.openInquiryModal(callback.TriggerID, callback.Channel.ID); err != nil {
				slog.Error("openInquiryModal failed", slog.Any("err", err))
			}
		case "history_action":
			if err := h.showInquiries(callback.Channel.ID, callback.User.ID); err != nil {
				slog.Error("showInquiries failed", slog.Any("err", err))
			}
		case "mention_action":
			if err := h.openMentionSettingModal(callback.TriggerID, callback.Channel.ID); err != nil {
				slog.Error("openMentionSettingModal failed", slog.Any("err", err))
			}
		}
	case slack.InteractionTypeViewSubmission:
		user, err := h.getUserInfo(callback.User.ID)
		if err != nil {
			slog.Error("GetUserInfo failed", slog.Any("err", err))
			return
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
			t, err := h.postInquiryRichMessage(channelID, priority, inputValue)
			if err != nil {
				slog.Error("postInquiryRichMessage failed", slog.Any("err", err))
				return
			}

			if err := h.saveInquiry(inputValue, t, channelID, callback.User.ID, userName); err != nil {
				slog.Error("saveInquiry failed", slog.Any("err", err))
				return
			}

		case "mention_setting_modal":
			mentionsRaw := callback.View.State.Values["mention_block"]["mention_text"].Value
			channelID := callback.View.PrivateMetadata
			err := h.saveMentionSetting(mentionsRaw, channelID, userName)
			if err != nil {
				slog.Error("saveMentionSetting failed", slog.Any("err", err))
				if _, err := h.client.PostEphemeral(
					channelID,
					callback.User.ID,
					slack.MsgOptionText(
						fmt.Sprintf(":warning: メンション設定の保存に失敗しました。\n```%s```", err.Error()),
						false,
					),
				); err != nil {
					slog.Error("Failed to post ephemeral message", slog.Any("err", err))
				}
			}
		}
	}

	w.WriteHeader(http.StatusOK)
}
