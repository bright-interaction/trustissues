# Stage 1: Build frontend
FROM oven/bun:1-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock* ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

# Stage 2: Build Go binary
FROM golang:1.26-alpine AS builder
RUN apk add --no-cache gcc musl-dev sqlite-dev
WORKDIR /app
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    go mod download
COPY . .

ARG SERVER_VERSION=dev
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build -ldflags "-s -w -X main.Version=${SERVER_VERSION}" \
    -o /trustissues ./cmd/server

# Stage 3: Minimal runtime
FROM alpine:3.21
RUN apk add --no-cache ca-certificates sqlite-libs tzdata \
    && addgroup -S trustissues && adduser -S trustissues -G trustissues
WORKDIR /app
COPY --from=builder /trustissues /app/trustissues
COPY --from=frontend /app/frontend/dist /app/frontend/dist
RUN mkdir -p /app/data && chown -R trustissues:trustissues /app
USER trustissues

ENV TRUSTISSUES_DATA_DIR=/app/data \
    TRUSTISSUES_FRONTEND_DIR=/app/frontend/dist \
    TRUSTISSUES_PORT=8080

EXPOSE 8080
VOLUME ["/app/data"]

ENTRYPOINT ["/app/trustissues"]
