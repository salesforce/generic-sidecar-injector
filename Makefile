all:
	go fmt ./...
	go test -mod=vendor -cover ./...


install: all
	go install -mod=vendor  ./cmd/...

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install -mod=vendor -ldflags "-s" -installsuffix cgo -v ./cmd/...


docker:
	docker build . -t sidecarinjector
