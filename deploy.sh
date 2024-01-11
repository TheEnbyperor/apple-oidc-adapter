#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "theenbyperor/wwfypc-apple-oidc:$VERSION" . || exit
docker push "theenbyperor/wwfypc-apple-oidc:$VERSION" || exit

sed -e "s/(version)/$VERSION/g" < deploy.yaml | kubectl apply -f - || exit
