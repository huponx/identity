GO  ?= go
BIN ?= bin
IMAGE_TAG  ?= dev
IMAGE_REPO ?= ghcr.io/huponx

.PHONY: help tidy upgrade outdated test vet build run e2e check-auth-ui docker clean

help:
	@printf '%s\n' \
		'tidy    go mod tidy' \
		'upgrade  upgrade the dependencies (PATCH=1: patch releases only), tidy, build and test' \
		'outdated  list the dependencies that have a newer version' \
		'test    go test -race ./...' \
		'vet     go vet ./...' \
		'build   identity and identity-setup into $(BIN)/' \
		'run     go run ./cmd/identity (reads the environment, see .env.example)' \
		'e2e     scripts/e2e.sh: code+PKCE, refresh reuse, token exchange against local Postgres/Redis' \
		'check-auth-ui  check that the auth-ui image tag of the Dockerfile exists' \
		'docker  build the image'

tidy:
	GOWORK=off $(GO) mod tidy

# Upgrade the dependencies to their latest minor/patch releases (PATCH=1: patch releases only), then tidy and
# check that everything still builds and passes. GOWORK=off: resolves against the module proxy, not the sibling
# folders of go.work. Review `git diff go.mod go.sum` before committing.
PATCH ?=
upgrade:
	GOWORK=off $(GO) get -u$(if $(PATCH),=patch) ./...
	GOWORK=off $(GO) mod tidy
	GOWORK=off $(GO) build ./...
	GOWORK=off $(GO) test ./...

# Lists the modules that have a newer version (nothing is changed).
outdated:
	@GOWORK=off $(GO) list -u -m -f '{{if and .Update (not .Indirect)}}{{.Path}} {{.Version}} -> {{.Update.Version}}{{end}}' all

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
