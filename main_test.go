package main

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	"github.com/slack-go/slack"
	"github.com/slack-go/slack/slackevents"
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

	handler.handleSlackEvents(rr, req)

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

	// メンション設定を保存しておく
	mentions := MentionSetting{
		Usernames: "user_id,group_id",
	}
	handler.db.Create(&mentions)

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

	mockClient.EXPECT().AuthTest().Return(&slack.AuthTestResponse{UserID: "bot_id"}, nil).AnyTimes()
	handler.client = mockClient
	handler.db.Exec("DELETE FROM inquiries")

	message := "test inquiry"
	timestamp := "12345"
	channelID := "channel_id"
	userID := "user_id"
	userName := "user_name"

	err = handler.saveInquiry(message, timestamp, channelID, userID, userName)
	assert.NoError(t, err)

	var inquiry Inquiry
	handler.db.First(&inquiry)
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

	handler.handleInteractions(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	if !ctrl.Satisfied() {
		t.Errorf("Not all expectations were met")
	}

}
