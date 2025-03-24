package infra

import "github.com/slack-go/slack"

type SlackAPI interface {
	PostMessage(channelID string, options ...slack.MsgOption) (string, string, error)
	OpenView(triggerID string, view slack.ModalViewRequest) (*slack.ViewResponse, error)
	AuthTest() (*slack.AuthTestResponse, error)
	GetUsers(options ...slack.GetUsersOption) ([]slack.User, error)
	GetUserGroups(options ...slack.GetUserGroupsOption) ([]slack.UserGroup, error)
	DeleteMessage(channelID, ts string) (string, string, error)
	GetUserInfo(userID string) (*slack.User, error)
	PostEphemeral(channelID, userID string, options ...slack.MsgOption) (string, error)
	GetConversationHistory(params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error)
	GetConversationReplies(params *slack.GetConversationRepliesParameters) ([]slack.Message, bool, string, error)
}
