# syntax=docker/dockerfile:1

FROM golang:1.26-alpine AS builder

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=docker
RUN CGO_ENABLED=0 GOFLAGS=-trimpath go build \
    -ldflags "-s -w -X main.version=${VERSION}" \
    -o /out/sinkhole-responder ./cmd/sinkhole-responder \
    && mkdir -p /out/data \
    && chown 65532:65532 /out/data

FROM scratch

LABEL org.opencontainers.image.title="Sinkhole Responder" \
      org.opencontainers.image.description="A hardened HTTP sinkhole responder for blocked resources" \
      org.opencontainers.image.source="https://git.kopenczei.net/arpad/sinkhole-responder" \
      org.opencontainers.image.licenses="MIT"

# The service makes no outbound TLS connections, so a scratch image without a CA
# certificate bundle is intentional.
# Web and responder assets are embedded in the binary; no separate asset build is needed.
COPY --from=builder --chown=65532:65532 /out/sinkhole-responder /sinkhole-responder
COPY --from=builder --chown=65532:65532 /out/data /data

# /data is the only writable path and holds both config and state. On an empty
# volume, the application seeds /data/config.yaml from its built-in defaults.
VOLUME ["/data"]

USER 65532:65532

EXPOSE 80 443 8080 8443

ENTRYPOINT ["/sinkhole-responder"]
CMD ["--config", "/data/config.yaml"]
