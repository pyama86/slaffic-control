package handler

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/pyama86/slaffic-control/domain/infra"
	"github.com/pyama86/slaffic-control/domain/model"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slacktest"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
)

func init() {
	defaultChannel = "test-channel"
}

func TestHandler_saveInquiry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	botID := randomString(10)
	mockClient := infra.NewMockSlackAPI(ctrl)

	handler, err := NewHandler()
	assert.NoError(t, err)

	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()
	handler.client = mockClient

	message := "test inquiry"
	timestamp := "12345"
	channelID := "channel_id"
	userID := "user_id"
	userName := "user_name"
	mention := "mention"
	err = handler.saveInquiry(message, timestamp, channelID, userID, userName, mention)
	assert.NoError(t, err)

	inquiries, err := handler.ds.GetLatestInquiries(botID)
	assert.NoError(t, err)
	inquiry := inquiries[0]

	assert.Equal(t, message, inquiry.Message)
	assert.Equal(t, timestamp, inquiry.Timestamp)
	assert.Equal(t, userID, inquiry.UserID)
}

func TestHandler_saveMentionSetting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	botID := randomString(10)

	// モックの作成
	mockClient := infra.NewMockSlackAPI(ctrl)

	// ハンドラーのセットアップ
	handler, err := NewHandler()
	assert.NoError(t, err)

	// モックのレスポンス設定
	mockClient.EXPECT().GetUsers().Return([]slack.User{{ID: "user1", Name: "user1"}}, nil).Times(1)
	mockClient.EXPECT().GetUserGroups().Return([]slack.UserGroup{{ID: "Sxxxx", Name: "group"}}, nil).Times(1)
	mockClient.EXPECT().PostMessage(gomock.Any(), gomock.Any()).Return("ok", "timestamp", nil).Times(1)
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()
	handler.client = mockClient

	// メンション設定の保存
	mentionsRaw := "@user1, @group"
	channelID := "channel_id"
	userName := "admin"

	err = handler.saveMentionSetting(mentionsRaw, channelID, userName)
	assert.NoError(t, err)
}

func TestHandler_showInquiries_SlackTest_Example(t *testing.T) {
	var postMessageRequests []map[string]interface{}
	botID := randomString(10)
	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}))

		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// まずは parse する
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			channel := r.FormValue("channel")
			user := r.FormValue("user")
			blocksJSON := r.FormValue("blocks")

			var blocks []map[string]interface{}
			if err := json.Unmarshal([]byte(blocksJSON), &blocks); err != nil {
				t.Errorf("failed to unmarshal blocks JSON: %v", err)
			}

			data := map[string]interface{}{
				"channel": channel,
				"user":    user,
				"blocks":  blocks,
			}
			postMessageRequests = append(postMessageRequests, data)

			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"ok": true, "message_ts": "1234567890.123456"}`))
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}

		}))
	})

	go server.Start()
	defer server.Stop()

	api := slack.New(
		"dummy-token",
		slack.OptionAPIURL(server.GetAPIURL()),
	)

	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	for i := 0; i < 21; i++ {
		_ = h.ds.SaveInquiry(&model.Inquiry{
			BotID:     botID,
			Message:   fmt.Sprintf("message #%d", i),
			Timestamp: fmt.Sprintf("99999999%d.000000", i),
			ThreadTS:  fmt.Sprintf("99999999%d.000000", i),
			ChannelID: "test-channel",
			UserID:    "test-user",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	err = h.showInquiries("test-channel", "test-user", "dummy-ts")
	assert.NoError(t, err, "showInquiries should not fail")

	assert.Len(t, postMessageRequests, 1, "Messageメッセージは1回のみ呼ばれるはず")

	req := postMessageRequests[0]
	assert.Equal(t, "test-channel", req["channel"])

	blocks, ok := req["blocks"].([]map[string]interface{})
	if !ok {
		t.Fatalf("blocks is not an array of map: %T", req["blocks"])
	}

	// blocks の中で "📝" と "📅" が含まれるSectionが問い合わせ行とみなす
	var inquiryCount int
	for _, b := range blocks {
		typ, _ := b["type"].(string)
		if typ == "section" {
			fields, _ := b["fields"].([]interface{})
			if fields == nil {
				continue
			}
			for _, f := range fields {
				field, _ := f.(map[string]interface{})
				txt, _ := field["text"].(string)
				if strings.Contains(txt, "投稿者") {
					inquiryCount++
				}

			}
		}
	}
	assert.Equal(t, 15, inquiryCount, "最新15件のみ表示されるはず")
}

func randomString(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[int(time.Now().UnixNano())%len(letters)]
	}
	return string(b)
}
func TestHandler_showInquiries_ExcludeDone(t *testing.T) {
	var postMessageRequests []map[string]interface{}
	botID := randomString(10)

	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}

		}))

		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// まずは parse する
			if err := r.ParseForm(); err != nil {
				t.Errorf("failed to parse form: %v", err)
			}
			channel := r.FormValue("channel")
			user := r.FormValue("user")
			blocksJSON := r.FormValue("blocks")

			var blocks []map[string]interface{}
			if err := json.Unmarshal([]byte(blocksJSON), &blocks); err != nil {
				t.Errorf("failed to unmarshal blocks JSON: %v", err)
			}

			data := map[string]interface{}{
				"channel": channel,
				"user":    user,
				"blocks":  blocks,
			}
			postMessageRequests = append(postMessageRequests, data)

			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(`{"ok": true, "message_ts": "1234567890.123456"}`))
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}))
	})

	go server.Start()
	defer server.Stop()

	api := slack.New(
		"dummy-token",
		slack.OptionAPIURL(server.GetAPIURL()),
	)

	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	for i := 0; i < 16; i++ {
		_ = h.ds.SaveInquiry(&model.Inquiry{
			BotID:     botID,
			Message:   fmt.Sprintf("message #%d", i),
			Timestamp: fmt.Sprintf("99999999%d.000000", i),
			ThreadTS:  fmt.Sprintf("99999999%d.000000", i),
			ChannelID: "test-channel",
			UserID:    "test-user",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	// 3件の問い合わせを "done" にする (最新3件)
	for i := 8; i < 11; i++ {
		ts := fmt.Sprintf("99999999%d.000000", i)
		err := h.ds.UpdateInquiryDone(botID, ts, true)
		assert.NoError(t, err, "UpdateInquiryDone should not fail")
	}

	err = h.showInquiries("test-channel", "test-user", "dummy-ts")
	assert.NoError(t, err, "showInquiries should not fail")

	assert.Len(t, postMessageRequests, 1, "Messageメッセージは1回のみ呼ばれるはず")

	req := postMessageRequests[0]
	assert.Equal(t, "test-channel", req["channel"])

	blocks, ok := req["blocks"].([]map[string]interface{})
	if !ok {
		t.Fatalf("blocks is not an array of map: %T", req["blocks"])
	}

	var inquiryCount int
	for _, b := range blocks {
		typ, _ := b["type"].(string)
		if typ == "section" {
			fields, _ := b["fields"].([]interface{})
			if fields == nil {
				continue
			}
			for _, f := range fields {
				field, _ := f.(map[string]interface{})
				txt, _ := field["text"].(string)
				if strings.Contains(txt, "投稿者") {
					inquiryCount++
				}

			}
		}
	}

	// 21件中 3件を "done" にしたので、表示されるのは 8件のはず
	assert.Equal(t, 13, inquiryCount, "未完了の問い合わせのみ表示されるべき")
}

func TestHandler_handleMention(t *testing.T) {
	// --- 1. Slackモックサーバの準備 ---
	var postMessagePayloads []map[string]interface{}
	var postEphemeralPayloads []map[string]interface{}
	botID := randomString(10)
	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		// /auth.test エンドポイント: botIDを返す
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
			assert.NoError(t, err)
		}))
		// /chat.postMessage エンドポイント: 通常メッセージ投稿をキャプチャ
		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			channel := r.FormValue("channel")
			blocksJSON := r.FormValue("blocks")
			text := r.FormValue("text")

			// JSONパース
			var blocks []map[string]interface{}
			if blocksJSON != "" {
				_ = json.Unmarshal([]byte(blocksJSON), &blocks)
			}
			data := map[string]interface{}{
				"channel": channel,
				"blocks":  blocks,
				"text":    text,
			}
			postMessagePayloads = append(postMessagePayloads, data)

			w.Header().Set("Content-Type", "application/json")
			resp := `{"ok":true,"ts":"1234.5678"}`
			_, _ = w.Write([]byte(resp))
		}))
		// /chat.conversations.history エンドポイント: 履歴取得をキャプチャ
		c.Handle("/conversations.history", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			w.Header().Set("Content-Type", "application/json")
			resp := `{"ok":true,"messages":[{"ts":"1234.5678","text":"test message"}]}`
			_, _ = w.Write([]byte(resp))
		}))
		// /chat.postEphemeral エンドポイント: エフェメラルメッセージ投稿をキャプチャ
		c.Handle("/chat.postEphemeral", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			channel := r.FormValue("channel")
			user := r.FormValue("user")
			blocksJSON := r.FormValue("blocks")
			text := r.FormValue("text")

			var blocks []map[string]interface{}
			if blocksJSON != "" {
				_ = json.Unmarshal([]byte(blocksJSON), &blocks)
			}
			data := map[string]interface{}{
				"channel": channel,
				"user":    user,
				"blocks":  blocks,
				"text":    text,
			}
			postEphemeralPayloads = append(postEphemeralPayloads, data)

			w.Header().Set("Content-Type", "application/json")
			resp := `{"ok":true,"message_ts":"9999.9999"}`
			_, _ = w.Write([]byte(resp))
		}))
	})

	go server.Start()
	defer server.Stop()

	// Slackクライアント生成
	api := slack.New("dummy-token", slack.OptionAPIURL(server.GetAPIURL()))

	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	// --- 3. テーブル駆動テスト ---
	tests := []struct {
		name          string
		messageText   string // BOTメンションを除去後の本文
		wantEphemeral bool   // 結果としてエフェメラルメッセージが投稿されるか
		wantInquiry   bool   // 結果としてDSに問い合わせが保存されるか
	}{
		{
			name:          "EmptyMessage",
			messageText:   "",
			wantEphemeral: true,
			wantInquiry:   false,
		},
		{
			name:          "NonEmptyMessage",
			messageText:   "問い合わせです！",
			wantEphemeral: false,
			wantInquiry:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 前回の結果をクリア
			postMessagePayloads = nil
			postEphemeralPayloads = nil

			// アプリメンションイベントを模擬
			event := &myEvent{
				User:    "U111",
				Channel: "C999",
				Text:    fmt.Sprintf("<@%s> %s", h.getBotUserID(), tt.messageText),
			}
			h.handleMention(event)

			// 結果検証
			// 1) エフェメラル投稿が期待通りか
			if tt.wantEphemeral {
				assert.Len(t, postEphemeralPayloads, 1, "エフェメラル投稿が1件あるはず")
			} else {
				assert.Len(t, postEphemeralPayloads, 0, "エフェメラル投稿はないはず")
			}

			// 2) 問い合わせが保存されるか
			inquiries, _ := h.ds.GetLatestInquiries(h.getBotUserID())
			if tt.wantInquiry {
				assert.Len(t, inquiries, 1, "問い合わせが1件保存されるはず")
				if len(inquiries) == 1 {
					assert.Equal(t, "問い合わせです！", inquiries[0].Message)
					assert.Equal(t, "U111", inquiries[0].UserID)
					assert.Equal(t, "C999", inquiries[0].ChannelID)
				}
				// 通常メッセージ投稿がされているか
				assert.Len(t, postMessagePayloads, 2, "chat.postMessage呼び出しが1回のはず")
			} else {
				assert.Len(t, inquiries, 0, "問い合わせは保存されないはず")
				assert.Len(t, postMessagePayloads, 0, "chat.postMessage呼び出しはないはず")
			}
		})
	}
}

func TestHandler_HandleInteractions_BlockActions(t *testing.T) {
	var postEphemeralPayloads []map[string]interface{}
	var viewsOpenPayloads []map[string]interface{}
	botID := randomString(10)

	// Slackモックサーバー
	srv := slacktest.NewTestServer(func(c slacktest.Customize) {
		// /auth.test
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
			assert.NoError(t, err)

		}))
		// /chat.postEphemeral
		c.Handle("/chat.postEphemeral", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			data := map[string]interface{}{
				"channel": r.FormValue("channel"),
				"user":    r.FormValue("user"),
				"text":    r.FormValue("text"),
				"blocks":  r.FormValue("blocks"),
			}
			postEphemeralPayloads = append(postEphemeralPayloads, data)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true}`))
		}))
		// /views.open
		c.Handle("/views.open", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			triggerID := r.FormValue("trigger_id")
			viewStr := r.FormValue("view")

			var viewData map[string]interface{}
			_ = json.Unmarshal([]byte(viewStr), &viewData)

			data := map[string]interface{}{
				"trigger_id": triggerID,
				"view":       viewData,
			}
			viewsOpenPayloads = append(viewsOpenPayloads, data)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok":true,"view":{"id":"V123"}}`))
		}))
	})

	go srv.Start()
	defer srv.Stop()

	api := slack.New("dummy-token", slack.OptionAPIURL(srv.GetAPIURL()))
	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	tests := []struct {
		name          string
		actionID      string
		wantEphemeral bool
		wantViewOpen  bool
	}{
		{
			name:         "OpenInquiryModal",
			actionID:     "inquiry_action",
			wantViewOpen: true,
		},
		{
			name:          "ShowInquiries",
			actionID:      "history_action",
			wantEphemeral: true,
		},
		{
			name:         "OpenMentionSettingModal",
			actionID:     "mention_action",
			wantViewOpen: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 毎テストごとに配列クリア
			postEphemeralPayloads = nil
			viewsOpenPayloads = nil

			callback := slack.InteractionCallback{
				Type: slack.InteractionTypeBlockActions,
				User: slack.User{ID: "U999"},
				Channel: slack.Channel{
					GroupConversation: slack.GroupConversation{
						Conversation: slack.Conversation{
							ID: "C999",
						},
					},
				},
				ActionCallback: slack.ActionCallbacks{
					BlockActions: []*slack.BlockAction{
						{
							ActionID: tt.actionID,
						},
					},
				},
				TriggerID: "TRIGGER_ABC",
			}

			h.handleInteractions(&callback)

			// ephemeral (履歴表示など)
			if tt.wantEphemeral {
				assert.Len(t, postEphemeralPayloads, 1, "エフェメラルメッセージ投稿が1回発生するはず")
			} else {
				assert.Len(t, postEphemeralPayloads, 0, "エフェメラルメッセージ投稿は発生しないはず")
			}

			// views.open
			if tt.wantViewOpen {
				assert.Len(t, viewsOpenPayloads, 1, "views.open が1回呼ばれるはず")
			} else {
				assert.Len(t, viewsOpenPayloads, 0, "views.open は呼ばれないはず")
			}
		})
	}
}

func TestHandler_HandleInteractions_ViewSubmission(t *testing.T) {
	var postMessagePayloads []map[string]interface{}
	var postEphemeralPayloads []map[string]interface{}

	tests := []struct {
		name         string
		callbackID   string
		viewState    map[string]map[string]slack.BlockAction
		wantMsgCount int  // postMessage呼び出し回数
		wantInqCount int  // Datastoreに保存される問い合わせ件数
		wantSetting  bool // mentionSetting が更新されるか
	}{
		{
			name:       "InquiryModal",
			callbackID: "inquiry_modal",
			viewState: map[string]map[string]slack.BlockAction{
				"inquiry_block":  {"inquiry_text": slack.BlockAction{Value: "モーダルからの問い合わせ"}},
				"priority_block": {"priority_select": slack.BlockAction{SelectedOption: slack.OptionBlockObject{Value: "ウルトラ"}}},
			},
			wantMsgCount: 2,
			wantInqCount: 1,
			wantSetting:  false,
		},
		{
			name:       "MentionSettingModal",
			callbackID: "mention_setting_modal",
			viewState: map[string]map[string]slack.BlockAction{
				"mention_block": {"mention_text": slack.BlockAction{Value: "@foo,@dev-team"}},
			},
			wantMsgCount: 1,
			wantInqCount: 0,
			wantSetting:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			botID := randomString(10)

			// Slackモックサーバ
			srv := slacktest.NewTestServer(func(c slacktest.Customize) {
				// /auth.test
				c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					w.Header().Set("Content-Type", "application/json")
					_, err := fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
					assert.NoError(t, err)
				}))

				// /chat.postMessage
				c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = r.ParseForm()
					channel := r.FormValue("channel")
					text := r.FormValue("text")
					blocksJSON := r.FormValue("blocks")
					var blocks []map[string]interface{}
					if blocksJSON != "" {
						_ = json.Unmarshal([]byte(blocksJSON), &blocks)
					}
					data := map[string]interface{}{
						"channel": channel,
						"text":    text,
						"blocks":  blocks,
					}
					postMessagePayloads = append(postMessagePayloads, data)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"ok":true,"ts":"9999.8888"}`))
				}))

				// /chat.postEphemeral
				c.Handle("/chat.postEphemeral", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					_ = r.ParseForm()
					channel := r.FormValue("channel")
					user := r.FormValue("user")
					text := r.FormValue("text")
					data := map[string]interface{}{
						"channel": channel,
						"user":    user,
						"text":    text,
					}
					postEphemeralPayloads = append(postEphemeralPayloads, data)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write([]byte(`{"ok":true}`))
				}))

				// /users.list
				c.Handle("/users.list", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					users := struct {
						OK    bool         `json:"ok"`
						Users []slack.User `json:"members"`
					}{
						OK: true,
						Users: []slack.User{
							{
								ID:   "U123",
								Name: "foo",
								Profile: slack.UserProfile{
									DisplayName: "Alice",
									RealName:    "Alice Smith",
								},
							},
						},
					}
					resp, _ := json.Marshal(users)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(resp)
				}))

				// /usergroups.list
				c.Handle("/usergroups.list", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					groups := struct {
						OK     bool              `json:"ok"`
						Groups []slack.UserGroup `json:"usergroups"`
					}{
						OK: true,
						Groups: []slack.UserGroup{
							{
								ID:     "S789",
								Name:   "developers",
								Handle: "dev-team",
							},
						},
					}
					resp, _ := json.Marshal(groups)
					w.Header().Set("Content-Type", "application/json")
					_, _ = w.Write(resp)
				}))
			})

			go srv.Start()
			defer srv.Stop()

			api := slack.New("dummy-token", slack.OptionAPIURL(srv.GetAPIURL()))
			h, err := NewHandler()
			assert.NoError(t, err)
			h.client = api

			postMessagePayloads = nil
			postEphemeralPayloads = nil

			// InteractionCallback(ViewSubmission)
			callback := slack.InteractionCallback{
				Type: slack.InteractionTypeViewSubmission,
				User: slack.User{
					ID: "U123",
					Profile: slack.UserProfile{
						DisplayName: "Tester",
						RealName:    "Tester Real",
					},
				},
				View: slack.View{
					CallbackID:      tt.callbackID,
					PrivateMetadata: "C999", // モーダルに紐づくchannelID
					State: &slack.ViewState{
						Values: tt.viewState,
					},
				},
			}

			h.handleInteractions(&callback)
			// --- postMessage が期待回数呼ばれたか
			assert.Len(t, postMessagePayloads, tt.wantMsgCount)

			// --- Datastore への問い合わせ保存数
			inquiries, _ := h.ds.GetLatestInquiries(h.getBotUserID())
			assert.Len(t, inquiries, tt.wantInqCount)

			// --- mentionSetting が更新されたか
			ms, _ := h.ds.GetMentionSetting(h.getBotUserID())
			if tt.wantSetting {
				// "foo" と "dev-team" が ID解決された結果が保存されている
				assert.Equal(t, "U123,S789", ms.Usernames, "メンション設定が正しく変換されているはず")
			} else {
				assert.Empty(t, ms.Usernames, "メンション設定は保存されないはず")
			}
		})
	}
}

func TestHandler_rotateMentions(t *testing.T) {
	t.Setenv("NEXT_ROTATION_MESSAGE", "%s から担当が変わります。")

	// Track messages posted to Slack
	var postMessagePayloads []map[string]interface{}
	botID := randomString(10)

	// Set up mock Slack server
	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		// Mock auth.test endpoint
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
		}))

		// Mock chat.postMessage endpoint
		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			channel := r.FormValue("channel")
			text := r.FormValue("text")
			blocksJSON := r.FormValue("blocks")

			data := map[string]interface{}{
				"channel": channel,
				"text":    text,
				"blocks":  blocksJSON,
			}
			postMessagePayloads = append(postMessagePayloads, data)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok": true, "ts": "1234567890.123456"}`))
		}))

		// Mock users.info endpoint
		c.Handle("/users.info", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			userID := r.FormValue("user")

			resp := fmt.Sprintf(`{
				"ok": true,
				"user": {
					"id": "%s",
					"name": "user%s",
					"real_name": "User %s",
					"profile": {
						"display_name": "Display User %s"
					}
				}
			}`, userID, userID[1:], userID[1:], userID[1:])

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(resp))
		}))

		// Mock usergroups.list endpoint
		c.Handle("/usergroups.list", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := `{
				"ok": true,
				"usergroups": [
					{
						"id": "S001",
						"name": "Team 1",
						"handle": "team1"
					},
					{
						"id": "S002",
						"name": "Team 2",
						"handle": "team2"
					}
				]
			}`

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(resp))
		}))
	})

	go server.Start()
	defer server.Stop()

	// Create handler with mock Slack client
	api := slack.New("dummy-token", slack.OptionAPIURL(server.GetAPIURL()))
	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	// Set up test mention settings
	testUsernames := "U001,S001,U002"
	err = h.ds.UpdateMentionSetting(botID, &model.MentionSetting{
		BotID:     botID,
		Usernames: testUsernames,
	})
	assert.NoError(t, err)

	// Execute the rotation
	h.botID = botID // Set botID directly to avoid auth.test call
	h.rotateMentions()

	// Verify that the rotation message was sent
	assert.GreaterOrEqual(t, len(postMessagePayloads), 2, "At least two messages should be sent")

	// First message should be the rotation message with mentions
	firstMsg := postMessagePayloads[1]
	assert.Equal(t, "test-channel", firstMsg["channel"])
	assert.Contains(t, firstMsg["text"], "<@U002>")

	// Verify that the rotation actually happened
	setting, err := h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "S001,U002,U001", setting.Usernames, "Usernames should be rotated")
}

func TestHandler_rotateMentions_WithoutMessage(t *testing.T) {
	t.Setenv("ROTATION_MESSAGE", "") // No rotation message

	// Track messages posted to Slack
	var postMessagePayloads []map[string]interface{}
	botID := randomString(10)

	// Set up mock Slack server
	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		// Mock auth.test endpoint
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
		}))

		// Mock chat.postMessage endpoint
		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			channel := r.FormValue("channel")
			text := r.FormValue("text")
			blocksJSON := r.FormValue("blocks")

			data := map[string]interface{}{
				"channel": channel,
				"text":    text,
				"blocks":  blocksJSON,
			}
			postMessagePayloads = append(postMessagePayloads, data)

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok": true, "ts": "1234567890.123456"}`))
		}))

		// Mock users.info endpoint
		c.Handle("/users.info", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			userID := r.FormValue("user")

			resp := fmt.Sprintf(`{
				"ok": true,
				"user": {
					"id": "%s",
					"name": "user%s",
					"real_name": "User %s",
					"profile": {
						"display_name": "Display User %s"
					}
				}
			}`, userID, userID[1:], userID[1:], userID[1:])

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(resp))
		}))

		// Mock usergroups.list endpoint
		c.Handle("/usergroups.list", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			resp := `{
				"ok": true,
				"usergroups": [
					{
						"id": "S001",
						"name": "Team 1",
						"handle": "team1"
					},
					{
						"id": "S002",
						"name": "Team 2",
						"handle": "team2"
					}
				]
			}`

			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(resp))
		}))
	})

	go server.Start()
	defer server.Stop()

	// Create handler with mock Slack client
	api := slack.New("dummy-token", slack.OptionAPIURL(server.GetAPIURL()))
	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api

	// Set up test mention settings
	testUsernames := "U001,S001,U002"
	err = h.ds.UpdateMentionSetting(botID, &model.MentionSetting{
		BotID:     botID,
		Usernames: testUsernames,
	})
	assert.NoError(t, err)

	// Execute the rotation
	h.botID = botID // Set botID directly to avoid auth.test call
	h.rotateMentions()

	// Verify that only the standard rotation message was sent (no custom message)
	assert.Equal(t, 1, len(postMessagePayloads), "Only one message should be sent")

	// Verify that the rotation actually happened
	setting, err := h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "S001,U002,U001", setting.Usernames, "Usernames should be rotated")
}

func TestHandler_rotateMentionsSilent(t *testing.T) {
	botID := randomString(10)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := infra.NewMockSlackAPI(ctrl)
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()

	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = mockClient
	h.botID = botID

	testUsernames := "U001,U002,U003"
	err = h.ds.UpdateMentionSetting(botID, &model.MentionSetting{
		BotID:     botID,
		Usernames: testUsernames,
	})
	assert.NoError(t, err)

	// サイレントローテーション実行
	h.rotateMentionsSilent()

	setting, err := h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "U002,U003,U001", setting.Usernames, "サイレントローテーションで先頭が末尾に移動するはず")

	// もう一回
	h.rotateMentionsSilent()
	setting, err = h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "U003,U001,U002", setting.Usernames)
}

func TestHandler_rotateMentionsSilent_SingleUser(t *testing.T) {
	botID := randomString(10)

	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := infra.NewMockSlackAPI(ctrl)
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()

	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = mockClient
	h.botID = botID

	// ユーザーが1人しかいない場合はローテーションしない
	err = h.ds.UpdateMentionSetting(botID, &model.MentionSetting{
		BotID:     botID,
		Usernames: "U001",
	})
	assert.NoError(t, err)

	h.rotateMentionsSilent()

	setting, err := h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "U001", setting.Usernames, "1人の場合はローテーションしない")
}

func TestHandler_perInquiryRotation(t *testing.T) {
	origMode := rotationMode
	rotationMode = "per_inquiry"
	defer func() { rotationMode = origMode }()

	var postMessagePayloads []map[string]interface{}
	botID := randomString(10)

	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
		}))
		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			data := map[string]interface{}{
				"channel": r.FormValue("channel"),
				"text":    r.FormValue("text"),
				"blocks":  r.FormValue("blocks"),
			}
			postMessagePayloads = append(postMessagePayloads, data)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok": true, "ts": "1234567890.123456"}`))
		}))
	})

	go server.Start()
	defer server.Stop()

	api := slack.New("dummy-token", slack.OptionAPIURL(server.GetAPIURL()))
	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api
	h.botID = botID

	// メンション設定をセットアップ
	err = h.ds.UpdateMentionSetting(botID, &model.MentionSetting{
		BotID:     botID,
		Usernames: "U001,U002,U003",
	})
	assert.NoError(t, err)

	// 問い合わせを作成
	h.handleMention(&myEvent{
		User:    "U111",
		Channel: "C999",
		Text:    fmt.Sprintf("<@%s> テスト問い合わせ", botID),
	})

	// per_inquiryモードでローテーションが実行されたか確認
	setting, err := h.ds.GetMentionSetting(botID)
	assert.NoError(t, err)
	assert.Equal(t, "U002,U003,U001", setting.Usernames, "per_inquiryモードで問い合わせ後にローテーションされるはず")

	// 最初の問い合わせはU001に割り当てられているはず
	inquiries, err := h.ds.GetLatestInquiries(botID)
	assert.NoError(t, err)
	assert.Len(t, inquiries, 1)
	assert.Equal(t, "U001", inquiries[0].AssingneeID)
}

func TestHandler_submitChangeHandler(t *testing.T) {
	var postMessagePayloads []map[string]interface{}
	botID := randomString(10)

	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)
		}))
		c.Handle("/chat.postMessage", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = r.ParseForm()
			data := map[string]interface{}{
				"channel": r.FormValue("channel"),
				"text":    r.FormValue("text"),
				"blocks":  r.FormValue("blocks"),
			}
			postMessagePayloads = append(postMessagePayloads, data)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"ok": true, "ts": "1234567890.123456"}`))
		}))
	})

	go server.Start()
	defer server.Stop()

	api := slack.New("dummy-token", slack.OptionAPIURL(server.GetAPIURL()))
	h, err := NewHandler()
	assert.NoError(t, err)
	h.client = api
	h.botID = botID

	// 問い合わせを作成
	inqTS := "9999999999.000000"
	err = h.ds.SaveInquiry(&model.Inquiry{
		BotID:       botID,
		Message:     "test inquiry",
		Timestamp:   inqTS,
		ChannelID:   "C999",
		UserID:      "U111",
		AssingneeID: "U001",
		CreatedAt:   time.Now(),
	})
	assert.NoError(t, err)

	// 担当者変更
	meta := fmt.Sprintf(`{"channel_id":"C999","inquiry_ts":"%s"}`, inqTS)
	callback := &slack.InteractionCallback{
		Type: slack.InteractionTypeViewSubmission,
		User: slack.User{ID: "U222"},
		View: slack.View{
			CallbackID:      "change_handler_modal",
			PrivateMetadata: meta,
			State: &slack.ViewState{
				Values: map[string]map[string]slack.BlockAction{
					"change_handler_block": {
						"change_handler_select": slack.BlockAction{SelectedUser: "U333"},
					},
				},
			},
		},
	}

	err = h.submitChangeHandler(callback)
	assert.NoError(t, err)

	// 問い合わせの担当者が変更されたか確認
	inquiry, err := h.ds.GetInquiry(botID, inqTS)
	assert.NoError(t, err)
	assert.Equal(t, "U333", inquiry.AssingneeID, "担当者がU333に変更されているはず")
	assert.Equal(t, "U333", inquiry.Mention)

	// 変更通知 + 変更ボタン = 2回のPostMessage
	assert.Len(t, postMessagePayloads, 2)
}
