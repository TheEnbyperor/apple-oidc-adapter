#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "theenbyperor/wwfypc-apple-oidc:$VERSION" . || exit
docker push "theenbyperor/wwfypc-apple-oidc:$VERSION" || exit

sentry-cli releases --org we-will-fix-your-pc new -p apple-oidc-adapter $VERSION || exit
sentry-cli releases --org we-will-fix-your-pc set-commits -c TheEnbyperor/apple-oidc-adapter $VERSION || exit

sed -e "s/(version)/$VERSION/g" < deploy.yaml | kubectl apply -f - || exit

sentry-cli releases --org we-will-fix-your-pc deploys $VERSION new -e prod