FROM golang:1.25-alpine AS builder

# Setup
RUN mkdir -p /go/src/github.com/madebymode/traefik-forward-auth
WORKDIR /go/src/github.com/madebymode/traefik-forward-auth

# Add libraries
RUN apk add --no-cache git

# Copy & build
ADD . /go/src/github.com/madebymode/traefik-forward-auth/
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GO111MODULE=on go build -a -installsuffix nocgo -o /traefik-forward-auth github.com/madebymode/traefik-forward-auth/cmd

# Create final secure runtime image
FROM alpine:latest
RUN addgroup -g 1001 -S nonroot && \
    adduser -u 1001 -S nonroot -G nonroot
COPY --from=builder /traefik-forward-auth /traefik-forward-auth
USER nonroot:nonroot
ENTRYPOINT ["/traefik-forward-auth"]
