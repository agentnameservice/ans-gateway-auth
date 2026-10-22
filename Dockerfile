FROM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod go mod download
COPY . .
ARG VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/ans-authz ./cmd/ans-authz

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
COPY --from=build /out/ans-authz /ans-authz
# The image ships no configuration: mount one at /etc/ans-authz/config.yaml.
# The gRPC listener keeps the loopback default unless the mounted file or
# ANS_AUTHZ_GRPC_LISTEN says otherwise; the HTTP listener binds all interfaces
# so probes and scrapes reach it.
ENV ANS_AUTHZ_HTTP_LISTEN=:9192
EXPOSE 9191 9192
USER 65532:65532
ENTRYPOINT ["/ans-authz"]
CMD ["--config", "/etc/ans-authz/config.yaml"]
