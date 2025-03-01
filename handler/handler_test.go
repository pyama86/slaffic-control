package handler

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/pyama86/slaffic-control/model"
	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
	"github.com/slack-go/slack/slacktest"
	"github.com/stretchr/testify/assert"
	gomock "go.uber.org/mock/gomock"
)

func createTimeStamp() int64 {
	return time.Now().Unix()
}

func createSlackSignature(timestamp int64, msgBody string) string {

	body := fmt.Sprintf("v0:%s:%s", strconv.FormatInt(timestamp, 10), msgBody)
	hash := hmac.New(sha256.New, []byte(os.Getenv("SLACK_SIGNING_SECRET")))
	hash.Write([]byte(body))

	sha := "v0=" + hex.EncodeToString(hash.Sum(nil))

	return sha
}

func TestHandler_handleSlackEvents(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	botID := randomString(10)

	// モックの作成
	mockClient := NewMockSlackAPI(ctrl)

	// ハンドラーのセットアップ
	handler, err := NewHandler()
	assert.NoError(t, err)

	// モックのレスポンス設定
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()
	mockClient.EXPECT().PostMessage(gomock.Any(), gomock.Any()).Return("ok", "timestamp", nil).AnyTimes()

	handler.client = mockClient

	body := `{"type":"url_verification","challenge":"test_challenge"}`
	ts := createTimeStamp()
	req := httptest.NewRequest(http.MethodPost, "/slack/events", bytes.NewBufferString(body))
	req.Header.Set("X-Slack-Signature", createSlackSignature(ts, body))
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))

	rr := httptest.NewRecorder()

	handler.HandleSlackEvents(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "test_challenge", rr.Body.String())
	if !ctrl.Satisfied() {
		t.Errorf("Not all expectations were met")
	}
}

func TestHandler_saveInquiry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	botID := randomString(10)
	mockClient := NewMockSlackAPI(ctrl)

	handler, err := NewHandler()
	assert.NoError(t, err)

	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: botID}, nil).AnyTimes()
	handler.client = mockClient

	message := "test inquiry"
	timestamp := "12345"
	channelID := "channel_id"
	userID := "user_id"
	userName := "user_name"

	err = handler.saveInquiry(message, timestamp, channelID, userID, userName)
	assert.NoError(t, err)

	inquiries, err := handler.ds.GetLatestInquiries(botID)
	assert.NoError(t, err)
	inquiry := inquiries[0]

	assert.Equal(t, message, inquiry.Message)
	assert.Equal(t, timestamp, inquiry.Timestamp)
	assert.Equal(t, userID, inquiry.UserID)
	assert.Equal(t, userName, inquiry.UserName)
}

func TestHandler_saveMentionSetting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()
	botID := randomString(10)

	// モックの作成
	mockClient := NewMockSlackAPI(ctrl)

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

// 認証のテストだけやる
func TestHandler_handleInteractions(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	handler, err := NewHandler()
	assert.NoError(t, err)

	body := `{"type":"url_verification","challenge":"test_challenge"}`
	ts := createTimeStamp()
	req := httptest.NewRequest(http.MethodPost, "/slack/events", bytes.NewBufferString(body))
	req.Header.Set("X-Slack-Signature", createSlackSignature(ts, body))
	req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))

	rr := httptest.NewRecorder()

	handler.HandleInteractions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	if !ctrl.Satisfied() {
		t.Errorf("Not all expectations were met")
	}
}

func TestHandler_showInquiries_SlackTest_Example(t *testing.T) {
	var postEphemeralRequests []map[string]interface{}
	botID := randomString(10)
	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}
		}))

		c.Handle("/chat.postEphemeral", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			postEphemeralRequests = append(postEphemeralRequests, data)

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

	for i := 0; i < 11; i++ {
		_ = h.ds.SaveInquiry(&model.Inquiry{
			BotID:     botID,
			Message:   fmt.Sprintf("message #%d", i),
			Timestamp: fmt.Sprintf("99999999%d.000000", i),
			ChannelID: "test-channel",
			UserID:    "test-user",
			UserName:  "Tester",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	err = h.showInquiries("test-channel", "test-user")
	assert.NoError(t, err, "showInquiries should not fail")

	assert.Len(t, postEphemeralRequests, 1, "Ephemeralメッセージは1回のみ呼ばれるはず")

	req := postEphemeralRequests[0]
	assert.Equal(t, "test-channel", req["channel"])
	assert.Equal(t, "test-user", req["user"])

	blocks, ok := req["blocks"].([]map[string]interface{})
	if !ok {
		t.Fatalf("blocks is not an array of map: %T", req["blocks"])
	}

	// blocks の中で "📝" と "📅" が含まれるSectionが問い合わせ行とみなす
	var inquiryCount int
	for _, b := range blocks {
		typ, _ := b["type"].(string)
		if typ == "section" {
			textObj, _ := b["text"].(map[string]interface{})
			txt, _ := textObj["text"].(string)
			if strings.Contains(txt, "📝") && strings.Contains(txt, "📅") {
				inquiryCount++
			}
		}
	}
	assert.Equal(t, 10, inquiryCount, "最新10件のみ表示されるはず")
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
	var postEphemeralRequests []map[string]interface{}
	botID := randomString(10)

	server := slacktest.NewTestServer(func(c slacktest.Customize) {
		c.Handle("/auth.test", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			_, err := w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
			if err != nil {
				t.Errorf("failed to write response: %v", err)
			}

		}))

		c.Handle("/chat.postEphemeral", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			postEphemeralRequests = append(postEphemeralRequests, data)

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

	// 11 件の問い合わせを作成
	for i := 0; i < 11; i++ {
		_ = h.ds.SaveInquiry(&model.Inquiry{
			BotID:     botID,
			Message:   fmt.Sprintf("message #%d", i),
			Timestamp: fmt.Sprintf("99999999%d.000000", i),
			ChannelID: "test-channel",
			UserID:    "test-user",
			UserName:  "Tester",
			CreatedAt: time.Now().Add(time.Duration(i) * time.Minute),
		})
	}

	// 3件の問い合わせを "done" にする (最新3件)
	for i := 8; i < 11; i++ {
		ts := fmt.Sprintf("99999999%d.000000", i)
		err := h.ds.UpdateInquiryDone(botID, ts, true)
		assert.NoError(t, err, "UpdateInquiryDone should not fail")
	}

	err = h.showInquiries("test-channel", "test-user")
	assert.NoError(t, err, "showInquiries should not fail")

	assert.Len(t, postEphemeralRequests, 1, "Ephemeralメッセージは1回のみ呼ばれるはず")

	req := postEphemeralRequests[0]
	assert.Equal(t, "test-channel", req["channel"])
	assert.Equal(t, "test-user", req["user"])

	blocks, ok := req["blocks"].([]map[string]interface{})
	if !ok {
		t.Fatalf("blocks is not an array of map: %T", req["blocks"])
	}

	// blocks の中で "📝" と "📅" が含まれるSectionが問い合わせ行とみなす
	var inquiryCount int
	for _, b := range blocks {
		typ, _ := b["type"].(string)
		if typ == "section" {
			textObj, _ := b["text"].(map[string]interface{})
			txt, _ := textObj["text"].(string)
			if strings.Contains(txt, "📝") && strings.Contains(txt, "📅") {
				inquiryCount++
			}
		}
	}

	// 11件中 3件を "done" にしたので、表示されるのは 8件のはず
	assert.Equal(t, 8, inquiryCount, "未完了の問い合わせのみ表示されるべき")
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
			_, err := w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
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
			event := &slackevents.AppMentionEvent{
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
				assert.Len(t, postMessagePayloads, 1, "chat.postMessage呼び出しが1回のはず")
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
			_, err := w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
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

			// payloadをJSONエンコード & formData化
			jsonBytes, _ := json.Marshal(callback)
			body := "payload=" + url.QueryEscape(string(jsonBytes))
			ts := createTimeStamp()
			// テスト用HTTPリクエスト
			req, _ := http.NewRequest(http.MethodPost, "/slack/interactions", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))
			req.Header.Set("X-Slack-Signature", createSlackSignature(ts, body))

			rr := httptest.NewRecorder()
			h.HandleInteractions(rr, req)

			// 検証
			assert.Equal(t, 200, rr.Code, "ハンドラは200を返すはず")

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
			wantMsgCount: 1,
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
					_, err := w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
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

			// JSON→form
			jsonBytes, _ := json.Marshal(callback)
			body := "payload=" + url.QueryEscape(string(jsonBytes))
			ts := createTimeStamp()

			req, _ := http.NewRequest(http.MethodPost, "/slack/interactions", bytes.NewBufferString(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.Header.Set("X-Slack-Request-Timestamp", strconv.FormatInt(ts, 10))
			req.Header.Set("X-Slack-Signature", createSlackSignature(ts, body))

			rr := httptest.NewRecorder()
			h.HandleInteractions(rr, req)
			assert.Equal(t, 200, rr.Code)

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
