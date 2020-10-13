all: fmt build test install

fmt:
	go fmt ./...

build:
	go build -mod=vendor -ldflags "-X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitHash=$(git rev-parse --short HEAD)' -X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitTag=$(git tag | tail -1)'" ./cmd/...

test:
	go test -mod=vendor -ldflags "-X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitHash=$(git rev-parse --short HEAD)' -X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitTag=$(git tag | tail -1)'" -cover ./...

install:
	go install -mod=vendor -ldflags "-X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitHash=$(git rev-parse --short HEAD)' -X 'github.com/salesforce/generic-sidecar-injector/pkg/metrics.gitTag=$(git tag | tail -1)'" ./cmd/...

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install -mod=vendor -ldflags "-s" -installsuffix cgo -v ./cmd/...

docker:
	docker build . -t sidecarinjector
