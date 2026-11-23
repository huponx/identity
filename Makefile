GO  ?= go
BIN ?= bin
IMAGE_TAG  ?= dev
IMAGE_REPO ?= ghcr.io/huponx

.PHONY: help tidy test vet build run e2e check-auth-ui docker clean

help:
	@printf '%s\n' \
		'tidy    go mod tidy' \
		'test    go test -race ./...' \
		'vet     go vet ./...' \
		'build   identity and identity-setup into $(BIN)/' \
		'run     go run ./cmd/identity (reads the environment, see .env.example)' \
		'e2e     scripts/e2e.sh: code+PKCE, refresh reuse, token exchange against local Postgres/Redis' \
		'check-auth-ui  check that the auth-ui image tag of the Dockerfile exists' \
		'docker  build the image'

tidy:
	GOWORK=off $(GO) mod tidy

test:
	$(GO) test -race ./...

vet:
	$(GO) vet ./...

build:
	@mkdir -p $(BIN)
	$(GO) build -o $(BIN)/identity ./cmd/identity
	$(GO) build -o $(BIN)/identity-setup ./cmd/identity-setup

run:
	$(GO) run ./cmd/identity

e2e:
	scripts/e2e.sh

check-auth-ui:
	scripts/check-auth-ui.sh

docker:
	docker build -f build/identity/Dockerfile -t $(IMAGE_REPO)/identity:$(IMAGE_TAG) .

clean:
	rm -rf $(BIN)
