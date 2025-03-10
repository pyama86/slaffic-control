package main

import (
	"log/slog"
	"os"

	"github.com/pyama86/slaffic-control/handler"
)

func init() {
	requiredEnv := []string{
		"SLACK_BOT_TOKEN",
		"SLACK_APP_TOKEN",
	}
	for _, env := range requiredEnv {
		if os.Getenv(env) == "" {
			slog.Error("required environment variable not set", slog.String("env", env))
			os.Exit(1)
		}
	}
}

func main() {
	h, err := handler.NewHandler()
	if err != nil {
		slog.Error("NewHandler failed", slog.Any("err", err))
		os.Exit(1)
	}

	// 自動ローテーション
	h.StartRotationMonitor()

	bind := ":3000"
	if os.Getenv("LISTEN_SOCKET") != "" {
		bind = os.Getenv("LISTEN_SOCKET")
	}
	slog.Info("Server listening", slog.String("bind", bind))
	if err := h.Handle(); err != nil {
		slog.Error("Server failed", slog.Any("err", err))
		os.Exit(1)
	}
}
