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

	// モックの作成
	mockClient := NewMockSlackAPI(ctrl)

	// ハンドラーのセットアップ
	handler, err := NewHandler()
	assert.NoError(t, err)

	// モックのレスポンス設定
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: "bot_id"}, nil).AnyTimes()
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

func TestHandler_handleMention(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockSlackAPI(ctrl)

	handler, err := NewHandler()
	assert.NoError(t, err)

	mockClient.EXPECT().PostMessage(gomock.Any(), gomock.Any()).Return("ok", "timestamp", nil).Times(1)
	mockClient.EXPECT().GetUserInfo("user_id").Return(&slack.User{Name: "user_name"}, nil).Times(1)
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: "bot_id"}, nil).AnyTimes()

	// メンション設定を保存しておく
	mentions := model.MentionSetting{
		Usernames: "user_id,group_id",
	}
	handler.ds.UpdateMentionSetting("", &mentions)

	handler.client = mockClient

	event := &slackevents.AppMentionEvent{
		User:    "user_id",
		Channel: "channel_id",
		Text:    "<@bot_id> test message",
	}

	handler.handleMention(event)
	if !ctrl.Satisfied() {
		t.Errorf("Not all expectations were met")
	}
}

func TestHandler_saveInquiry(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockClient := NewMockSlackAPI(ctrl)

	handler, err := NewHandler()
	assert.NoError(t, err)

	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: "bot_id_save"}, nil).AnyTimes()
	handler.client = mockClient

	message := "test inquiry"
	timestamp := "12345"
	channelID := "channel_id"
	userID := "user_id"
	userName := "user_name"

	err = handler.saveInquiry(message, timestamp, channelID, userID, userName)
	assert.NoError(t, err)

	inquiries, err := handler.ds.GetLatestInquiries("bot_id_save")
	inquiry := inquiries[0]

	assert.Equal(t, message, inquiry.Message)
	assert.Equal(t, timestamp, inquiry.Timestamp)
	assert.Equal(t, userID, inquiry.UserID)
	assert.Equal(t, userName, inquiry.UserName)
}

func TestHandler_saveMentionSetting(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	// モックの作成
	mockClient := NewMockSlackAPI(ctrl)

	// ハンドラーのセットアップ
	handler, err := NewHandler()
	assert.NoError(t, err)

	// モックのレスポンス設定
	mockClient.EXPECT().GetUsers().Return([]slack.User{{ID: "user1", Name: "user1"}}, nil).Times(1)
	mockClient.EXPECT().GetUserGroups().Return([]slack.UserGroup{{ID: "Sxxxx", Name: "group"}}, nil).Times(1)
	mockClient.EXPECT().PostMessage(gomock.Any(), gomock.Any()).Return("ok", "timestamp", nil).Times(1)
	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: "bot_id"}, nil).AnyTimes()
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
			w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
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
			_, _ = w.Write([]byte(`{"ok": true, "message_ts": "1234567890.123456"}`))
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

	_ = h.getBotUserID()

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
			w.Write([]byte(fmt.Sprintf(`{"ok": true, "user_id": "%s", "team_id": "T1234"}`, botID)))
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
			_, _ = w.Write([]byte(`{"ok": true, "message_ts": "1234567890.123456"}`))
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

	_ = h.getBotUserID()

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
