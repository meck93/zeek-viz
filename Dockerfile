# Build argument to control final base image
# DEBUG_BUILD=true -> Alpine (default, easier debugging with shell)
# DEBUG_BUILD=false -> Scratch (production, minimal size)
ARG DEBUG_BUILD=false

# Go build stage
FROM golang:1.25.0-alpine AS go-builder
RUN apk add --no-cache git ca-certificates tzdata
WORKDIR /app

# Copy go dependencies
COPY go.mod ./
COPY go.su[m] ./
RUN go mod download

# Copy source code
COPY main.go ./
COPY handlers/ ./handlers/
COPY models/ ./models/
COPY static/ ./static/

# Build arguments for versioning
ARG COMMIT_HASH
ARG BUILD_TIMESTAMP

# Build the binary with embedded static files
RUN --mount=type=cache,target=/root/.cache/go-build \
    --mount=type=cache,target=/go/pkg \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s" \
    -a \
    -o ./zeek-viz .

# Dependencies stage - CA certificates and timezone data
FROM alpine:latest AS deps
RUN apk --no-cache add ca-certificates tzdata

# Production base (scratch - minimal size)
FROM scratch AS base-false

# Debug base (Alpine - with shell and tools) - DEFAULT
FROM alpine:latest AS base-true
RUN apk --no-cache add ca-certificates tzdata

# Choose base image: base-true (Alpine) by default, base-false (scratch) for production
FROM base-${DEBUG_BUILD}

# Add the (statically linked) tini binary to the image
# Download tini with SHA256 checksum verification for security
ADD --chown=65532:65532 --chmod=755 --checksum=sha256:c5b0666b4cb676901f90dfcb37106783c5fe2077b04590973b885950611b30ee https://github.com/krallin/tini/releases/download/v0.19.0/tini-static /tini

# For scratch builds, add CA certificates and timezone data
COPY --from=deps /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=deps /usr/share/zoneinfo /usr/share/zoneinfo

WORKDIR /app

# Copy application binary
COPY --from=go-builder /app/zeek-viz ./zeek-viz

# Create non-root user
USER 65532:65532

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/zeek-viz", "-h"] || exit 1

# Use tini as entrypoint for proper signal handling
ENTRYPOINT ["/tini", "-g", "--"]

# Start the application
CMD ["./zeek-viz"]