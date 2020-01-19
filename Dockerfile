FROM golang:1.13 AS build

WORKDIR /sidecarinjector
COPY go.mod go.sum ./

RUN go mod download

COPY cmd ./cmd
COPY pkg ./pkg

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-s" -installsuffix cgo -o sidecarinjector ./cmd/sidecarinjector

FROM gcr.io/distroless/base
COPY --from=build /sidecarinjector/sidecarinjector /sidecarinjector
ENV PATH="/:${PATH}"
CMD ["/sidecarinjector"]
