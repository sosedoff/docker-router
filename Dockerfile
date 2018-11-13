FROM alpine:3.6
LABEL maintainer="Dan Sosedoff <dan.sosedoff@gmail.com>"

RUN \
  apk update && \
  apk add --no-cache ca-certificates openssl postgresql wget && \
  update-ca-certificates

WORKDIR /beam
ADD beam /beam/beam

EXPOSE 80
EXPOSE 443

CMD ["/beam/beam"]
