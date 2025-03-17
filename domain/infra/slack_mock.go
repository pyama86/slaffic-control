// Code generated by MockGen. DO NOT EDIT.
// Source: domain/infra/slack.go
//
// Generated by this command:
//
//	mockgen -source=domain/infra/slack.go -destination=domain/infra/slack_mock.go -package=infra
//

// Package infra is a generated GoMock package.
package infra

import (
	reflect "reflect"

	slack "github.com/slack-go/slack"
	gomock "go.uber.org/mock/gomock"
)

// MockSlackAPI is a mock of SlackAPI interface.
type MockSlackAPI struct {
	ctrl     *gomock.Controller
	recorder *MockSlackAPIMockRecorder
	isgomock struct{}
}

// MockSlackAPIMockRecorder is the mock recorder for MockSlackAPI.
type MockSlackAPIMockRecorder struct {
	mock *MockSlackAPI
}

// NewMockSlackAPI creates a new mock instance.
func NewMockSlackAPI(ctrl *gomock.Controller) *MockSlackAPI {
	mock := &MockSlackAPI{ctrl: ctrl}
	mock.recorder = &MockSlackAPIMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use.
func (m *MockSlackAPI) EXPECT() *MockSlackAPIMockRecorder {
	return m.recorder
}

// AuthTest mocks base method.
func (m *MockSlackAPI) AuthTest() (*slack.AuthTestResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "AuthTest")
	ret0, _ := ret[0].(*slack.AuthTestResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// AuthTest indicates an expected call of AuthTest.
func (mr *MockSlackAPIMockRecorder) AuthTest() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "AuthTest", reflect.TypeOf((*MockSlackAPI)(nil).AuthTest))
}

// GetConversationHistory mocks base method.
func (m *MockSlackAPI) GetConversationHistory(params *slack.GetConversationHistoryParameters) (*slack.GetConversationHistoryResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetConversationHistory", params)
	ret0, _ := ret[0].(*slack.GetConversationHistoryResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetConversationHistory indicates an expected call of GetConversationHistory.
func (mr *MockSlackAPIMockRecorder) GetConversationHistory(params any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetConversationHistory", reflect.TypeOf((*MockSlackAPI)(nil).GetConversationHistory), params)
}

// GetUserGroups mocks base method.
func (m *MockSlackAPI) GetUserGroups(options ...slack.GetUserGroupsOption) ([]slack.UserGroup, error) {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUserGroups", varargs...)
	ret0, _ := ret[0].([]slack.UserGroup)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserGroups indicates an expected call of GetUserGroups.
func (mr *MockSlackAPIMockRecorder) GetUserGroups(options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserGroups", reflect.TypeOf((*MockSlackAPI)(nil).GetUserGroups), options...)
}

// GetUserInfo mocks base method.
func (m *MockSlackAPI) GetUserInfo(userID string) (*slack.User, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "GetUserInfo", userID)
	ret0, _ := ret[0].(*slack.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUserInfo indicates an expected call of GetUserInfo.
func (mr *MockSlackAPIMockRecorder) GetUserInfo(userID any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUserInfo", reflect.TypeOf((*MockSlackAPI)(nil).GetUserInfo), userID)
}

// GetUsers mocks base method.
func (m *MockSlackAPI) GetUsers(options ...slack.GetUsersOption) ([]slack.User, error) {
	m.ctrl.T.Helper()
	varargs := []any{}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "GetUsers", varargs...)
	ret0, _ := ret[0].([]slack.User)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// GetUsers indicates an expected call of GetUsers.
func (mr *MockSlackAPIMockRecorder) GetUsers(options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "GetUsers", reflect.TypeOf((*MockSlackAPI)(nil).GetUsers), options...)
}

// OpenView mocks base method.
func (m *MockSlackAPI) OpenView(triggerID string, view slack.ModalViewRequest) (*slack.ViewResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "OpenView", triggerID, view)
	ret0, _ := ret[0].(*slack.ViewResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// OpenView indicates an expected call of OpenView.
func (mr *MockSlackAPIMockRecorder) OpenView(triggerID, view any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "OpenView", reflect.TypeOf((*MockSlackAPI)(nil).OpenView), triggerID, view)
}

// PostEphemeral mocks base method.
func (m *MockSlackAPI) PostEphemeral(channelID, userID string, options ...slack.MsgOption) (string, error) {
	m.ctrl.T.Helper()
	varargs := []any{channelID, userID}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PostEphemeral", varargs...)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PostEphemeral indicates an expected call of PostEphemeral.
func (mr *MockSlackAPIMockRecorder) PostEphemeral(channelID, userID any, options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{channelID, userID}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostEphemeral", reflect.TypeOf((*MockSlackAPI)(nil).PostEphemeral), varargs...)
}

// PostMessage mocks base method.
func (m *MockSlackAPI) PostMessage(channelID string, options ...slack.MsgOption) (string, string, error) {
	m.ctrl.T.Helper()
	varargs := []any{channelID}
	for _, a := range options {
		varargs = append(varargs, a)
	}
	ret := m.ctrl.Call(m, "PostMessage", varargs...)
	ret0, _ := ret[0].(string)
	ret1, _ := ret[1].(string)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// PostMessage indicates an expected call of PostMessage.
func (mr *MockSlackAPIMockRecorder) PostMessage(channelID any, options ...any) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	varargs := append([]any{channelID}, options...)
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PostMessage", reflect.TypeOf((*MockSlackAPI)(nil).PostMessage), varargs...)
}
