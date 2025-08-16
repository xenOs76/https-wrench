#!/usr/bin/env bash

nix flake update

cd src || exit
go get -u
go mod tidy
