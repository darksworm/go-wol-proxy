FROM golang:1.20-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o go-wol-proxy .

# Create a minimal runtime image
FROM alpine:3.17

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/go-wol-proxy /app/

# Expose the default port
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/go-wol-proxy", "/app/config.toml"]
