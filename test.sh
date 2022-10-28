#!/usr/bin/bash

set -euxo pipefail

GOOS=linux GOARCH=amd64 go build -o validate-token main.go

kubectl apply -f resources/

kubectl wait -n test-jwts --for=condition=ready pod validator
kubectl wait -n test-jwts --for=condition=ready pod pod-projected-token
kubectl wait -n test-jwts --for=condition=ready pod pod-static-token

mkdir -p ./tmp

kubectl exec -it -n test-jwts pod-static-token cat /var/run/secrets/kubernetes.io/serviceaccount/token > ./tmp/static-token
kubectl exec -it -n test-jwts pod-projected-token cat /var/run/secrets/tokens/my-token > ./tmp/projected-token

kubectl cp -n test-jwts ./validate-token validator:/validate-token
kubectl cp -n test-jwts ./tmp/static-token validator:/static-token
kubectl cp -n test-jwts ./tmp/projected-token validator:/projected-token

kubectl exec -it -n test-jwts validator -- /validate-token
kubectl exec -it -n test-jwts validator -- /validate-token --token /projected-token
kubectl exec -it -n test-jwts validator -- /validate-token --token /static-token

