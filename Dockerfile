FROM golang:1.26-alpine AS builder

ARG VERSION=dev

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w -X main.version=${VERSION}" -o gatekeeper ./cmd/gatekeeper

FROM alpine:latest

RUN apk add --no-cache ca-certificates tzdata

WORKDIR /app
COPY --from=builder /build/gatekeeper .

VOLUME ["/data"]
EXPOSE 8080

ENTRYPOINT ["./gatekeeper"]
