# Stage 1: Build frontend
FROM oven/bun:1-alpine AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/bun.lock* ./
RUN --mount=type=cache,target=/root/.bun/install/cache \
    bun install --frozen-lockfile
COPY frontend/ ./
RUN bun run build

# Stage 2: Build Go binary
# Pinned to the patch, not the floating 1.26 minor.
#
# The floating tag resolved forward at build time, so which stdlib a given
# image shipped depended on whether the base layer happened to be evicted
# before that build -- decidable only by reading the binary afterwards, and
# recorded nowhere. This makes it a property of the repository instead.
# 1.26.6 is the version measured to clear every stdlib advisory govulncheck
# reports as reachable from this module.
#
# Held in lockstep with go.mod's `go` directive -- NOT a `toolchain` line,
# which this module deliberately no longer carries because it is inert under
# the GOTOOLCHAIN=local that every official golang image bakes in -- and with
# the go-version pin in .github/workflows/ci.yml. internal/buildpins asserts
# all three agree and refuses if any drifts.
FROM golang:1.26.6-alpine AS builder
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
# `sqlite` (the CLI) as well as `sqlite-libs` (the shared library the binary
# links against). The documented backup procedure runs
# `docker compose exec trustissues sqlite3 ... ".backup ..."`, which is the only
# WAL-safe way to snapshot a live database, and without the CLI that command
# exits 127. ~1 MB. The `sqlite3 --version` assertion below keeps it from being
# dropped again.
RUN apk add --no-cache ca-certificates sqlite sqlite-libs tzdata \
    && sqlite3 --version \
    && addgroup -S trustissues && adduser -S trustissues -G trustissues
WORKDIR /app
COPY --from=builder /trustissues /app/trustissues
COPY --from=frontend /app/frontend/dist /app/frontend/dist
RUN mkdir -p /app/data && chown -R trustissues:trustissues /app
USER trustissues

# Bind 0.0.0.0 INSIDE the container only. The container network namespace
# isolates this listener; reachability is still controlled at publish time
# (docker-compose publishes to host loopback only) or via the internal Docker
# network. On bare metal the app defaults to 127.0.0.1 instead.
ENV TRUSTISSUES_DATA_DIR=/app/data \
    TRUSTISSUES_FRONTEND_DIR=/app/frontend/dist \
    TRUSTISSUES_BIND_HOST=0.0.0.0 \
    TRUSTISSUES_PORT=8080

EXPOSE 8080
VOLUME ["/app/data"]

ENTRYPOINT ["/app/trustissues"]
