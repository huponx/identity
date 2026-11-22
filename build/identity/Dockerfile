# syntax=docker/dockerfile:1
# Build context is the repository root:
#   docker build -f build/identity/Dockerfile -t identity:dev .
ARG GO_VERSION=1.26

FROM --platform=$BUILDPLATFORM golang:${GO_VERSION} AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG TARGETOS=linux
ARG TARGETARCH=amd64
RUN --mount=type=cache,target=/go/pkg/mod --mount=type=cache,target=/root/.cache/go-build \
    GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o /out/identity ./cmd/identity && GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "-s -w" -o /out/identity-setup ./cmd/identity-setup

# static + CA certificates, runs as non-root
FROM gcr.io/distroless/static-debian13:nonroot
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="identity" \
      org.opencontainers.image.source="https://github.com/huponx/identity" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"
COPY --from=build /out/identity /identity
COPY --from=build /out/identity-setup /identity-setup
EXPOSE 9090 8080
USER nonroot:nonroot
ENTRYPOINT ["/identity"]
