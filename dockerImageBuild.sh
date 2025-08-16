#!/usr/bin/env bash

docker build -t https-wrench . || exit 1

DOCKER_RUN="docker run --rm https-wrench --help"
echo -e "Running the following command: $DOCKER_RUN\n"
$DOCKER_RUN
