.PHONY: lint fmt
LINTER := golangci-lint
run:
	go run .


lint:
	@echo ">> Running linter ($(LINTER))"
	$(LINTER) run

fmt:
	@echo ">> Formatting code"
	gofmt -w .
	goimports -w .


devdeps:
	@echo ">> Installing development dependencies"
	which goimports > /dev/null || go install golang.org/x/tools/cmd/goimports@latest
	which golangci-lint > /dev/null || go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
