## Playground with kube JWTs

This repo contains my experiments with Kubernetes JWTs:
- kubernetes manifests to create fixtures pods/service accounts and their tokens
- go progran that:
  - manually fetches Kubernetes JWKs
  - manually validate Kubernetes-issued JWTs (only check signature)
  - uses the Kubernetes `TokenReview` API to perform token validation
- a script that bootstraps everything

### Requirements

- go
- kubectl connected to a working cluster
- bash

### Usage

```
./test.sh
```
