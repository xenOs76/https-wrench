FROM golang:1.24.4 AS builder

WORKDIR /app

COPY src/go.mod src/go.sum ./
RUN go mod download

COPY src/ .
COPY .git .

RUN APP_VERSION=$(git describe --tags || echo '0.0.0') &&\ 
    GO_MODULE_NAME=$(awk '/^module / { print $2 }' go.mod) &&\
    CGO_ENABLED=0 GOOS=linux go build -o https-wrench -ldflags "-X  $GO_MODULE_NAME/cmd.version=$APP_VERSION" . 

FROM alpine:3.18

RUN apk --no-cache add ca-certificates

WORKDIR /root/

COPY --from=builder /app/https-wrench .

ENTRYPOINT ["./https-wrench"]
