
IMAGE ?= ghcr.io/madebymode/traefik-forward-auth

build:
	go build ./...

format:
	gofmt -w -s internal/*.go internal/provider/*.go cmd/*.go

test:
	go test -v ./...

docker-build:
	docker build -t $(IMAGE):dev .

.PHONY: build format test docker-build
