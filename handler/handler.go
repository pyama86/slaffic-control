package handler

import (
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/jellydator/ttlcache/v3"
	_ "github.com/mattn/go-sqlite3"
	"github.com/pyama86/slaffic-control/domain/infra"
	"github.com/pyama86/slaffic-control/domain/model"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/socketmode"
)

var defaultChannel = os.Getenv("DEFAULT_CHANNEL")

const (
	cmdHistory = "history"
	cmdSummary = "summary"
)

type Handler struct {
	client        infra.SlackAPI
	userCache     *ttlcache.Cache[string, []slack.User]
	groupCache    *ttlcache.Cache[string, []slack.UserGroup]
	userInfoCache *ttlcache.Cache[string, *slack.User]
	ds            infra.Datastore
	botID         string
}

func NewHandler() (*Handler, error) {
	var ds infra.Datastore
	var err error
	if os.Getenv("DB_DRIVER") == "dynamodb" {
		ds, err = infra.NewDynamoDB()
		if err != nil {
			return nil, err
		}
	} else {
		ds, err = infra.NewDataBase()
		if err != nil {
			return nil, err
		}
	}

	api := slack.New(os.Getenv("SLACK_BOT_TOKEN"))
	h := &Handler{
		client:        api,
		userCache:     ttlcache.New(ttlcache.WithTTL[string, []slack.User](time.Hour)),
		groupCache:    ttlcache.New(ttlcache.WithTTL[string, []slack.UserGroup](time.Hour)),
		userInfoCache: ttlcache.New(ttlcache.WithTTL[string, *slack.User](24 * time.Hour)),
		ds:            ds,
	}
	go h.userCache.Start()
	go h.groupCache.Start()
	go h.userInfoCache.Start()
	return h, nil
}

func (h *Handler) Handle() error {
	webApi := slack.New(
		os.Getenv("SLACK_BOT_TOKEN"),
		slack.OptionAppLevelToken(os.Getenv("SLACK_APP_TOKEN")),
	)
	socketMode := socketmode.New(
		webApi,
	)
	authTest, authTestErr := webApi.AuthTest()
	if authTestErr != nil {
		fmt.Fprintf(os.Stderr, "SLACK_BOT_TOKEN is invalid: %v\n", authTestErr)
		os.Exit(1)
	}
	h.botID = authTest.UserID

	go func() {
		for envelope := range socketMode.Events {
			switch envelope.Type {
			case socketmode.EventTypeEventsAPI:
				socketMode.Ack(*envelope.Request)
				eventPayload, ok := envelope.Data.(slackevents.EventsAPIEvent)
				if !ok {
					slog.Error("Failed to cast to EventsAPIEvent")
					continue
				}
				h.handleCallBack(&eventPayload)
			case socketmode.EventTypeInteractive:
				socketMode.Ack(*envelope.Request)
				callback, ok := envelope.Data.(slack.InteractionCallback)
				if !ok {
					slog.Error("Failed to cast to InteractionCallback")
					continue
				}
				h.handleInteractions(&callback)
			default:
				socketMode.Debugf("Skipped: %v", envelope.Type)
			}
		}
	}()

	return socketMode.Run()
}

func getUserPreferredName(user *slack.User) string {
	if user.Profile.DisplayName != "" {
		return user.Profile.DisplayName
	}
	if user.RealName != "" {
		return user.RealName
	}
	return user.Name
}

func (h *Handler) saveInquiryAndNotify(channelID, userID, priority, inputValue, ts, threadTS string) error {
	mention, err := h.getMentionLink()
	if err != nil {
		return fmt.Errorf("getMention failed: %w", err)
	}
	mentionID, err := h.getMentionID()
	if err != nil {
		return fmt.Errorf("getMentionID failed: %w", err)
	}
	t, err := h.postInquiryRichMessage(channelID, userID, priority, inputValue, threadTS, mention)
	if err != nil {
		return fmt.Errorf("postInquiryRichMessage failed: %w", err)
	}

	if err := h.saveInquiry(inputValue, t, channelID, userID, mentionID, threadTS); err != nil {
		return fmt.Errorf("saveInquiry failed: %w", err)
	}

	// ハンドラを募集する
	if _, _, err := h.client.PostMessage(
		channelID,
		slack.MsgOptionTS(t),
		slack.MsgOptionBlocks(h.personInChargeMessage(t)...),
	); err != nil {
		return fmt.Errorf("failed to post person in charge message: %w", err)
	}
	return nil

}
func (h *Handler) handleInteractions(callback *slack.InteractionCallback) {
	switch callback.Type {
	case slack.InteractionTypeBlockActions:
		if len(callback.ActionCallback.BlockActions) < 1 {
			return
		}
		action := callback.ActionCallback.BlockActions[0]

		switch action.ActionID {
		case "inquiry_action":
			if err := h.openInquiryModal(callback.TriggerID, callback.Channel.ID); err != nil {
				slog.Error("openInquiryModal failed", slog.Any("err", err))

				return
			}
		case "history_action":
			if err := h.showInquiries(callback.Channel.ID, callback.User.ID, callback.ActionCallback.BlockActions[0].Value); err != nil {
				slog.Error("showInquiries failed", slog.Any("err", err))
				return
			}
		case "mention_action":
			if err := h.openMentionSettingModal(callback.TriggerID, callback.Channel.ID); err != nil {
				slog.Error("openMentionSettingModal failed", slog.Any("err", err))
				return
			}
		case "handler_button":
			if err := h.submitHandler(callback.User.ID, callback.Channel.ID, action.Value); err != nil {
				slog.Error("submitHandler failed", slog.Any("err", err))
				return
			}
		}

	case slack.InteractionTypeViewSubmission:
		user, err := h.getUserInfo(callback.User.ID)
		if err != nil {
			slog.Error("GetUserInfo failed", slog.Any("err", err))
			return
		}

		// 投稿者の名前（表示名があれば優先）
		author := getUserPreferredName(user)

		switch callback.View.CallbackID {
		case "inquiry_modal":
			// 問い合わせの受付
			inputValue := callback.View.State.Values["inquiry_block"]["inquiry_text"].Value
			priority := callback.View.State.Values["priority_block"]["priority_select"].SelectedOption.Value
			channelID := callback.View.PrivateMetadata

			if strings.HasPrefix(channelID, "D") {
				_, err := h.client.PostEphemeral(
					channelID,
					callback.User.ID,
					slack.MsgOptionText(
						":warning: ダイレクトメッセージへの問い合わせはできません。",
						false,
					),
				)
				if err != nil {
					slog.Error("Failed to post ephemeral message", slog.Any("err", err))
				}
				return
			}

			err := h.saveInquiryAndNotify(channelID, callback.User.ID, priority, inputValue, callback.MessageTs, "")
			if err != nil {
				slog.Error("saveInquiryAndNotify failed", slog.Any("err", err))
				return
			}
		case "mention_setting_modal":
			// メンションの保存
			mentionsRaw := callback.View.State.Values["mention_block"]["mention_text"].Value
			channelID := callback.View.PrivateMetadata
			err := h.saveMentionSetting(mentionsRaw, channelID, author)
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
					return
				}
			}
		}
	}
}

func (h *Handler) handleCallBack(event *slackevents.EventsAPIEvent) {
	switch event.Type {
	case slackevents.CallbackEvent:
		innerEvent := event.InnerEvent
		switch ev := innerEvent.Data.(type) {
		case *slackevents.MessageEvent:
			// DMでメンションされたとき
			if ev.ChannelType == "im" && strings.Contains(ev.Text, fmt.Sprintf("<@%s>", h.getBotUserID())) {
				h.handleMention(&myEvent{
					Channel: ev.Channel,
					User:    ev.User,
					Text:    ev.Text,
				})
			}
		case *slackevents.AppMentionEvent:
			h.handleMention(&myEvent{
				Channel:   ev.Channel,
				User:      ev.User,
				Text:      ev.Text,
				ThreadTS:  ev.ThreadTimeStamp,
				TimeStamp: ev.TimeStamp,
			})
		case *slackevents.ReactionAddedEvent:
			if ev.Reaction == "white_check_mark" {
				h.handleReaction(true, ev.Item.Timestamp)
			}
		case *slackevents.ReactionRemovedEvent:
			if ev.Reaction == "white_check_mark" {
				h.handleReaction(false, ev.Item.Timestamp)
			}
		}
	default:
		slog.Warn("Unsupported EventsAPIEvent type", slog.Any("type", event.Type))
	}
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

func (h *Handler) getMention(isLink bool) (string, error) {
	setting, err := h.ds.GetMentionSetting(h.getBotUserID())
	if err != nil {
		return "", err
	}
	mention := "未設定"
	if setting.BotID != "" && setting.Usernames != "" {
		if isLink {
			mention, err = setting.GetCurrentMention()
		} else {
			mention, err = setting.GetCurrentMentionID()
		}
		if err != nil {
			return "", err
		}
	}
	return mention, nil

}

func (h *Handler) getMentionLink() (string, error) {
	return h.getMention(true)
}

func (h *Handler) getMentionID() (string, error) {
	return h.getMention(false)
}

func (h *Handler) postInquiryRichMessage(channelID, userID, priority, content, threadTs, mention string) (string, error) {
	blocks := []slack.Block{
		// ヘッダー
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "📩 新しい問い合わせ", false, false),
		),
		slack.NewDividerBlock(),
		// 問い合わせ作成ユーザー
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*👤 投稿者:* <@%s>", userID), false, false),
			nil, nil,
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
		slack.NewContextBlock("context_block",
			[]slack.MixedElement{
				slack.NewTextBlockObject("mrkdwn", "問い合わせに関するやり取りはこのメッセージのスレッドで進行してください。", false, false),
				slack.NewTextBlockObject("mrkdwn", "✅のリアクションを付けると、この問い合わせは履歴から表示されなくなります。", false, false),
			}...,
		),
	}

	var t string
	var err error
	if threadTs != "" {
		// スレッドに返信
		_, t, err = h.client.PostMessage(
			channelID,
			slack.MsgOptionBlocks(blocks...),
			slack.MsgOptionTS(threadTs),
		)
	} else {
		_, t, err = h.client.PostMessage(channelID, slack.MsgOptionBlocks(blocks...))
	}

	if err != nil {
		return "", err
	}
	return t, nil
}

// 担当者を募るメッセージ
func (h *Handler) personInChargeMessage(inqTs string) []slack.Block {
	return []slack.Block{
		slack.NewHeaderBlock(
			slack.NewTextBlockObject("plain_text", "🚨 担当者募集！", false, false),
		),
		slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "💻 問い合わせを主に担当するメンバーを募集しています", false, false),
			nil,
			nil,
		),
		slack.NewDividerBlock(),
		slack.NewActionBlock(
			"handler_action",
			slack.NewButtonBlockElement(
				"handler_button",
				inqTs,
				slack.NewTextBlockObject("plain_text", "👋 担当者は私です！", false, false),
			).WithStyle(slack.StylePrimary),
		),
	}
}

func (h *Handler) openMentionSettingModal(triggerID, channelID string) error {
	titleText := slack.NewTextBlockObject("plain_text", "メンション設定", false, false)
	submitText := slack.NewTextBlockObject("plain_text", "保存", false, false)
	closeText := slack.NewTextBlockObject("plain_text", "キャンセル", false, false)

	existing, err := h.ds.GetMentionSetting(h.getBotUserID())
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

func timeNow() time.Time {
	loc, err := time.LoadLocation("Asia/Tokyo")
	if err != nil {
		loc = time.UTC
	}
	return time.Now().In(loc)
}

func (h *Handler) saveInquiry(message, timestamp, channelID, userID, mention, threadTS string) error {
	return h.ds.SaveInquiry(&model.Inquiry{
		BotID:     h.getBotUserID(),
		Message:   message,
		Timestamp: timestamp,
		ThreadTS:  threadTS,
		ChannelID: channelID,
		UserID:    userID,
		Mention:   mention,
		CreatedAt: timeNow(),
	})
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
	return "", "", fmt.Errorf("user or group not found: %s", name)
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
	if err := h.ds.UpdateMentionSetting(h.getBotUserID(), &model.MentionSetting{
		Usernames: finalCSV,
		CreatedAt: timeNow(),
	}); err != nil {
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

func (h *Handler) showInquiries(channelID, userID, threadTS string) error {
	inquiries, err := h.ds.GetLatestInquiries(h.getBotUserID())
	if err != nil {
		if _, err := h.client.PostEphemeral(channelID, userID, slack.MsgOptionText("📭 *問い合わせ履歴の取得に失敗しました*", false)); err != nil {
			return err
		}
		return err
	}

	if len(inquiries) == 0 {
		if _, err := h.client.PostEphemeral(channelID, userID, slack.MsgOptionText("📭 *問い合わせ履歴はありません*", false)); err != nil {
			return err
		}
		return nil
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
		slackURL := fmt.Sprintf("%s/archives/%s/p%s", workspaceURL, i.ChannelID, strings.ReplaceAll(i.Timestamp, ".", ""))
		if i.ThreadTS != "" {
			slackURL += fmt.Sprintf("?thread_ts=%s&cid=%s", i.ThreadTS, i.ChannelID)
		}
		// 投稿者名の取得（メンションが飛ばないように）
		postedBy := "不明"
		user, err := h.getUserInfo(i.UserID)
		if err == nil {
			postedBy = getUserPreferredName(user)
		} else {
			slog.Error("GetUserInfo failed", slog.Any("err", err))
		}

		// 担当者
		// メンションの取得

		personInChage := i.Mention
		userID := i.Mention
		if strings.HasPrefix(i.Mention, "S") || strings.HasPrefix(i.Mention, "G") {
			userID = i.Mention
		} else if strings.HasPrefix(i.Mention, "<@") {
			// ユーザーIDから名前を取得
			if strings.TrimPrefix(i.Mention, "<!subteam^") == "" {
				// ユーザーグループのメンション
				userID := strings.TrimPrefix(i.Mention, "<!subteam^")
				userID = strings.TrimSuffix(userID, ">")
			} else if strings.HasPrefix(i.Mention, "<@") {
				userID = strings.TrimPrefix(i.Mention, "<@")
				userID = strings.TrimSuffix(userID, ">")
			}
		}
		if userID != "" {
			pc, err := h.getUserInfo(userID)
			if err != nil {
				slog.Error("GetUserInfo failed", slog.Any("err", err))
			}
			personInChage = getUserPreferredName(pc)
		}

		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", "📅 *問い合わせ日時:* "+t, false, false),
			[]*slack.TextBlockObject{
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*投稿者:* %s", postedBy), false, false),
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*担当者:* %s", personInChage), false, false),
				slack.NewTextBlockObject("mrkdwn", fmt.Sprintf("*詳細:* <%s|詳細を見る>", slackURL), false, false),
			},
			nil,
		))

		blocks = append(blocks, slack.NewSectionBlock(
			slack.NewTextBlockObject("mrkdwn", i.Message, false, false),
			nil,
			nil,
		))

		blocks = append(blocks, slack.NewDividerBlock())
	}

	// コンテキスト（履歴の上限について）
	blocks = append(blocks, slack.NewContextBlock("",
		slack.NewTextBlockObject("mrkdwn",
			"📌 *最新 10 件の履歴を表示しています*",
			false, false),
	))

	_, _, err = h.client.PostMessage(
		channelID,
		slack.MsgOptionBlocks(blocks...),
		slack.MsgOptionTS(threadTS),
	)
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

	loc, err := time.LoadLocation("Asia/Tokyo") // 日本時間
	if err != nil {
		slog.Error("Failed to load location", slog.Any("err", err))
		os.Exit(1)
		return
	}

	go func() {
		for {
			now := timeNow()
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
			now = timeNow() // スリープ後に再取得
			if int(now.Weekday()) == desiredDay {
				slog.Info("Rotation time has come, start rotation")
				h.rotateMentions()
			}
		}
	}()
}

func (h *Handler) rotateMentions() {
	setting, err := h.ds.GetMentionSetting(h.getBotUserID())
	if err != nil {
		slog.Error("Failed to get latest mention setting", slog.Any("err", err))
	}

	if setting.BotID == "" || setting.Usernames == "" {
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
	if err := h.ds.UpdateMentionSetting(h.getBotUserID(), setting); err != nil {
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
	if h.botID == "" {
		authResp, err := h.client.AuthTest()
		if err != nil {
			slog.Error("Failed to get bot user ID", slog.Any("err", err))
			return ""
		}
		slog.Info("Bot user ID", slog.Any("id", authResp.UserID))
		h.botID = authResp.UserID
	}
	return h.botID
}

func (h *Handler) handleReaction(done bool, timestamp string) {
	if err := h.ds.UpdateInquiryDone(h.getBotUserID(), timestamp, done); err != nil {
		slog.Error("Failed to update inquiry", slog.Any("err", err), slog.String("timestamp", timestamp), slog.Bool("done", done))
	}
	slog.Info("Inquiry update", slog.String("timestamp", timestamp), slog.Bool("done", done))
}

type myEvent struct {
	Channel   string `json:"channel"`
	Text      string `json:"text"`
	User      string `json:"user"`
	TimeStamp string `json:"ts"`
	ThreadTS  string `json:"thread_ts"`
}

// メンションを受け取ったときの処理
func (h *Handler) handleMention(event *myEvent) {
	channelID := event.Channel
	userID := event.User

	// ボット自身のメンション (`@bot`) を削除
	messageText := strings.Replace(event.Text, fmt.Sprintf("<@%s>", h.getBotUserID()), "", 1)
	messageText = strings.TrimSpace(messageText) // 余計なスペースを削除
	// 問い合わせをリッチメッセージで投稿
	// スレッドでメンションされたか？
	var threadTs string
	if event.ThreadTS != "" {
		threadTs = event.ThreadTS
	}
	ts := event.TimeStamp
	if event.ThreadTS != "" {
		ts = event.ThreadTS
	}
	if messageText == cmdHistory {
		if err := h.showInquiries(channelID, userID, ts); err != nil {
			slog.Error("showInquiries failed", slog.Any("err", err))
		}
		return
	}

	if threadTs != "" {
		mentionTS, err := h.firstMentionIn(
			channelID,
			event.ThreadTS,
			h.getBotUserID(),
		)

		if err != nil {
			slog.Error("firstMentionIn failed", slog.Any("err", err))
			return
		}

		if mentionTS != "" {
			setting, err := h.ds.GetMentionSetting(h.getBotUserID())
			if err != nil {
				return
			}
			mention, err := setting.GetCurrentMention()
			if err != nil {
				return
			}
			// 同じメンションで催促するだけ
			_, _, err = h.client.PostMessage(
				channelID,
				slack.MsgOptionText(
					fmt.Sprintf("%s さん、回答をお待ちしています。", mention),
					false,
				),
				slack.MsgOptionTS(event.ThreadTS),
			)
			if err != nil {
				slog.Error("Failed to post message", slog.Any("err", err))
			}

			return
		}
	}

	// もしメンションにテキストが含まれていれば、問い合わせとして処理
	if messageText != "" && !strings.HasPrefix(event.Channel, "D") {
		priority := "未設定"
		err := h.saveInquiryAndNotify(channelID, userID, priority, messageText, event.TimeStamp, threadTs)
		if err != nil {
			slog.Error("saveInquiryAndNotify failed", slog.Any("err", err))
			return
		}

		return
	}

	// ここまで来たら、通常のメニューを表示

	blocks := []slack.Block{
		newSectionBlock("inq", "*メニューを選択してください*", "inquiry_action", "問い合わせを行う", ts),
		newSectionBlock("hist", "*問い合わせの履歴を見る*", "history_action", "履歴を見る", ts),
		newSectionBlock("mention", "*メンションの設定を行う*", "mention_action", "設定する", ts),
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

func newSectionBlock(blockID, text, actionID, buttonText, value string) *slack.SectionBlock {
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
				Value:    value,
				Text: &slack.TextBlockObject{
					Type: "plain_text",
					Text: buttonText,
				},
			},
		},
	}
}

// インシデントハンドラーが応募されたら、保存してハンドラに必要なことを通知する
func (h *Handler) submitHandler(userID, channelID, ts string) error {
	// 問い合わせを検索
	inquiry, err := h.ds.GetInquiry(h.getBotUserID(), ts)
	if err != nil {
		return fmt.Errorf("GetInquiry failed: %w", err)
	}

	// ハンドラを保存
	if inquiry != nil {
		inquiry.Mention = userID
		if err := h.ds.SaveInquiry(inquiry); err != nil {
			return fmt.Errorf("UpdateInquiry failed: %w", err)
		}
		slog.Info("Inquiry updated", slog.String("botID", h.getBotUserID()), slog.String("userID", userID), slog.String("channelID", channelID), slog.String("ts", ts))
	} else {
		slog.Warn("Inquiry not found", slog.String("botID", h.getBotUserID()), slog.String("userID", userID), slog.String("channelID", channelID), slog.String("ts", ts))
	}

	blocks := []slack.Block{
		slack.NewSectionBlock(
			slack.NewTextBlockObject(
				"mrkdwn",
				fmt.Sprintf(
					":wave: <@%s> さん、担当者になっていただきありがとうございます！",
					userID,
				),
				false,
				false,
			),
			nil,
			nil,
		),
	}

	// メッセージを送信
	if _, _, err := h.client.PostMessage(
		channelID,
		slack.MsgOptionTS(ts),
		slack.MsgOptionBlocks(blocks...),
	); err != nil {
		return fmt.Errorf("PostMessage failed: %w", err)
	}

	return nil
}

func (h *Handler) firstMentionIn(channelID, threadTs, mention string) (string, error) {
	history, err := h.client.GetConversationHistory(&slack.GetConversationHistoryParameters{
		ChannelID: channelID,
		Inclusive: true,
		Latest:    threadTs,
		Limit:     1,
		Oldest:    threadTs,
	})

	if err != nil {
		return "", fmt.Errorf("GetConversationHistory failed: %w", err)
	}
	if len(history.Messages) == 0 {
		return "", fmt.Errorf("No messages found in thread")
	}

	for _, msg := range history.Messages {
		if strings.Contains(msg.User, mention) || strings.Contains(msg.BotID, mention) {
			return msg.Timestamp, nil
		}
	}
	return "", nil
}
