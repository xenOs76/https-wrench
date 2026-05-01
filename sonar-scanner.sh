#!/usr/bin/env bash

export SONAR_TOKEN=$(cat /home/xeno/.config/https-wrench/sonar_token_https-wrench)

sonar-scanner -Dsonar.organization=xenos76 \
  -Dsonar.projectKey=xenOs76_https-wrench \
  -Dsonar.go.coverage.reportPaths=cover.out \
  -Dsonar.exclusions=completions/**,.devenv/**,.direnv/** \
  -D"sonar.tests=." \
  -D"sonar.test.inclusions=*_test.go,**/*_test.go"
