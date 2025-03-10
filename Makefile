.PHONY: lint fmt ci test devdeps mockgen
LINTER := golangci-lint
build:
	go build -o bin/ .
ci: devdeps lint test
run:
	go run .


lint:
	@echo ">> Running linter ($(LINTER))"
	$(LINTER) run

fmt:
	@echo ">> Formatting code"
	gofmt -w .
	goimports -w .

test:
	@echo ">> Running tests"
	@rm -rf db/test.db
	@DB_PATH=$(shell pwd)/db/test.db SLACK_BOT_TOKEN=dummy SLACK_APP_TOKEN=dummy go test -v ./...

devdeps:
	@echo ">> Installing development dependencies"
	which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	which mockgen > /dev/null || go install go.uber.org/mock/mockgen@latest

mockgen:
	mockgen -source=main.go -destination=slack_mock.go -package=main
