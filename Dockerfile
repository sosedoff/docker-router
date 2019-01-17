# ------------------------------------------------------------------------------
# Build Phase
# ------------------------------------------------------------------------------

FROM golang:1.11 AS build

ADD . /go/src/github.com/sosedoff/docker-router
WORKDIR /go/src/github.com/sosedoff/docker-router

RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o /docker-router

# ------------------------------------------------------------------------------
# Package Phase
# ------------------------------------------------------------------------------

FROM alpine:3.6

RUN \
  apk update && \
  apk add --no-cache ca-certificates openssl wget && \
  update-ca-certificates

COPY --from=build /docker-router /bin/docker-router

EXPOSE 80
EXPOSE 443

CMD ["/bin/docker-router"]