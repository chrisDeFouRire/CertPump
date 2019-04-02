FROM golang:1.12 as builder

ENV GO111MODULE=on

# setup the working directory
WORKDIR /go/src/github.com/chrisDeFouRire/CertPump
COPY go.sum go.mod ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o CertPump ./CertPump.go

# use a minimal alpine image
FROM alpine:3.7
# add ca-certificates in case you need them
RUN apk update && apk add ca-certificates && rm -rf /var/cache/apk/*
# set working directory
WORKDIR /root
# copy the binary from builder
COPY --from=builder /go/src/github.com/chrisDeFouRire/CertPump/CertPump .
# run the binary
CMD ["./CertPump"]
