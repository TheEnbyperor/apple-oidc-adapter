#!/usr/bin/env bash

VERSION=$(sentry-cli releases propose-version || exit)

docker build -t "theenbyperor/as207960-apple-oidc:$VERSION" . || exit
docker push "theenbyperor/as207960-apple-oidc:$VERSION" || exit

sed -e "s/(version)/$VERSION/g" < deploy.yaml | kubectl apply -f - || exit
