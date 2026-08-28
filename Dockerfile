FROM golang:1.23-alpine AS builder

WORKDIR /app

# Copy go.mod and go.sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -o doormouse .

# Create a minimal runtime image
FROM alpine:3.22

WORKDIR /app

# Copy the binary from the builder stage
COPY --from=builder /app/doormouse /app/

# Expose the default port. TCP routes listen on their own ports; with
# network_mode: host they are reachable directly, otherwise publish each one.
EXPOSE 8080

# Run the application
ENTRYPOINT ["/app/doormouse", "/app/config.toml"]
