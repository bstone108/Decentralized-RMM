CGO_ENABLED ?= 0
export CGO_ENABLED

.PHONY: test spike proof build vet

test:
	go test ./...

spike:
	go test -count=1 -v ./internal/spike ./internal/store

proof:
	go test -count=1 -v ./internal/node -run TestTwoNodeAuthenticatedIntentAck
	go test -count=1 -v ./internal/consolegui ./internal/consolemesh

vet:
	go vet ./...

build:
	go build -trimpath -o bin/rmm-agent ./cmd/rmm-agent
	go build -trimpath -o bin/rmm-console ./cmd/rmm-console
	go build -trimpath -o bin/rmm-pack ./cmd/rmm-pack
	go build -trimpath -o bin/rmm ./cmd/rmm
