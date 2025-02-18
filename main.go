package main

import (
	"log/slog"
	"net/http"
	"os"

	"github.com/pyama86/slaffic-control/handler"
)

func init() {
	requiredEnv := []string{
		"SLACK_BOT_TOKEN",
		"SLACK_SIGNING_SECRET",
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

	http.HandleFunc("/slack/events", h.HandleSlackEvents)
	http.HandleFunc("/slack/interactions", h.HandleInteractions)

	// 自動ローテーション
	h.StartRotationMonitor()

	bind := ":3000"
	if os.Getenv("LISTEN_SOCKET") != "" {
		bind = os.Getenv("LISTEN_SOCKET")
	}
	slog.Info("Server listening", slog.String("bind", bind))
	if err := http.ListenAndServe(bind, nil); err != nil {
		slog.Error("Server failed", slog.Any("err", err))
		os.Exit(1)
	}
}
