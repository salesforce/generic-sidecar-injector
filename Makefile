all:
	go fmt ./...
	go test -cover ./...


install: all
	go install ./cmd/...

linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go install -ldflags "-s" -installsuffix cgo -v ./cmd/...


docker:
	docker build . -t sidecarinjector
