# Dockerfile
FROM golang:1.20-alpine AS builder
RUN apk add --no-cache git build-base
WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /server server.go

FROM alpine:3.18
RUN apk add --no-cache ca-certificates
COPY --from=builder /server /server
WORKDIR /data
VOLUME ["/data"]
EXPOSE 5555
ENTRYPOINT ["/server"]
