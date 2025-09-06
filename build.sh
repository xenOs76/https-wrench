#!/usr/bin/env bash

test -d dist || mkdir dist

cd src || exit
APP_VERSION=$(git describe --tags || echo '0.0.0') &&
    GO_MODULE_NAME=$(grep module go.mod | awk '{ print $2 }') &&
    CGO_ENABLED=0 GOOS=linux go build -o ../dist/https-wrench -ldflags "-X $GO_MODULE_NAME/cmd.version=$APP_VERSION" main.go
