#!/usr/bin/env bash

sonar-scanner -Dsonar.organization=xenos76 \
  -Dsonar.projectKey=xenOs76_https-wrench \
  -Dsonar.go.coverage.reportPaths=cover.out \
  -Dsonar.exclusions=completions/**,.devenv/**,.direnv/** \
  -D"sonar.tests=." \
  -D"sonar.test.inclusions=*_test.go,**/*_test.go"
