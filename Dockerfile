############################
# STEP 1 build executable binary
############################
FROM golang:alpine AS builder
RUN apk update && apk add --no-cache ca-certificates tzdata && update-ca-certificates

WORKDIR /src

# Download the dependencies
COPY ./go.mod ./go.sum ./
RUN go mod download

# Import the source files
COPY . .

# Build the binary for the application
RUN go generate ./... && \
  CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
  -installsuffix 'static' \
  -ldflags '-w -s' \
  -o /go/bin/main ./cmd/

############################
# STEP 2 build a small image
############################
FROM scratch

# Import the tls certificates and timezone data from the builder.
COPY --from=builder /usr/share/zoneinfo /usr/share/zoneinfo
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

# Import the user and group files from the builder.
COPY --from=builder /etc/passwd /etc/passwd
COPY --from=builder /etc/group /etc/group

# Import the application binaries
COPY --from=builder /go/bin/main /main

# Use an unprivileged user.
USER nobody:nobody

ENTRYPOINT ["/main"]
