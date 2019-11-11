# docker-router

Routing proxy for Docker containers with native LetsEncrypt support

*NOTE: This is an experimental project and it not intended for production - use at your own risk*

## Overview

Docker router project is designed for a specific purpose - to route and load balance
HTTP traffic across docker containers, with automatic LetsEncrypt support. It's also
intended to be as much config-less as possible. While there are many other docker-based
load balancers/routers on the market (traefik, fabio, nginx-gen, etc) docker-router
aims to be extremely simple with a limited number of features.

### Single host use only

Docker router is intended to be used on a single machine, so if you're planning 
on load balancing traffic to containers located on different machines you might need
to consider other solutions (traefik/fabio).

### No centralized store

Dynamic routes are pulled off docker configuration, meaning docker-router will
inspect all existing (running) containers and detemine which ones should be live.
All internal configuration state is stored in memory only and will be rebuilt during
service restarts.

### Automatic SSL with LetsEncrypt

Original goal of the project was to automatically enable SSL termination via LetsEncrypt
certificate management and remove the need to manage that part manually or via 
other dependencies like `certbot`.

### Simple Configuration

Docker router does not support reading configuration from a file and all configuration
must be done via environment variables (for host) and docker labels (for containers). 
To make a container discoverable add the following labels when starting it:

```bash
docker run \
  --label router.domain=myapp.com
  myapp
```

## Usage

Start the proxy container:

```
docker run \
  -d \
  --name=router \
  --restart=always \
  -p 80:80 \
  -p 443:443 \
  --net=app \
  -e HTTP_PORT=80 \
  -e HTTPS_PORT=443 \
  -e DOCKER_NETWORK=app \
  -e LETSENCRYPT_EMAIL=...YOUR EMAIL... \
  -e LETSENCRYPT_CERTS_DIR=/certs \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /root/certs:/certs \
  sosedoff/docker-router
```

To route HTTP requests to your containers, start them with options:

```
docker run \
  --name=myapp \
  --restart=always \
  -d \
  -e PORT=5000 \
  --label=router.domain=myawesomeapp.com \
  --label=router.healthcheck=/heartbeat \
  --net=app \
  myapp
```

## Debugging

To see the internal routing state and table, add `DEBUG=1` env var when starting `docker-proxy`.

You should be able to open `http://router-hostname/_router/info` endpoint.

Example:

```json
{
  "accesstime": {
    "06bf3fd503ca419f18e4d175d5143fcadc79389f918288f995d785da2320bb8b": "2019-04-26T16:48:38.12782292Z",
    "41a2b6cfaf5822d743a6ae0a178d1b3cd32e5534d274310e75eb21fc68eaa5e4": "2019-04-26T16:57:06.655900487Z",
    "518a0dc6ca67837954f08c20ad2dec48904b508728d456eeeba7bafab8f88cab": "2019-04-26T16:57:06.958181838Z"
  },
  "mapping": {
    "41a2b6cfaf5822d743a6ae0a178d1b3cd32e5534d274310e75eb21fc68eaa5e4": "myawesomeapp.com@*",
    "518a0dc6ca67837954f08c20ad2dec48904b508728d456eeeba7bafab8f88cab": "myawesomeapp.com@*",
    "751d7b4a32a02cd56d8f1009d490e2d3b13d62da3b2a90ea609563e63ea69398": "myawesomeapp.com@*"
  },
  "routes": {
    "myawesomeapp.com": {
      "*": {
        "targets": [
          {
            "id": "751d7b4a32a02cd56d8f1009d490e2d3b13d62da3b2a90ea609563e63ea69398",
            "endpoint": "172.20.0.3:5000",
            "count": 0,
            "conns": 0
          },
          {
            "id": "41a2b6cfaf5822d743a6ae0a178d1b3cd32e5534d274310e75eb21fc68eaa5e4",
            "endpoint": "172.20.0.4:5000",
            "count": 0,
            "conns": 0
          },
          {
            "id": "518a0dc6ca67837954f08c20ad2dec48904b508728d456eeeba7bafab8f88cab",
            "endpoint": "172.20.0.5:5000",
            "count": 0,
            "conns": 0
          }
        ],
        "total": 24
      }
    }
  }
}
```

## Features

### Basic Authentication

To enable basic authentication, add the following labels with starting docker containers:

```bash
docker run \
  ...
  --label auth.user=myuser \
  --label auth.password=mypass \
  ...
  myimages
```

Password protection will be enabled for all targets within a route. Both username
and password labels must be correct otherwise the password authentication is going
to be skipped.

### Prefix-based Routing

Instead of running different application/containers via subdomains you can use
a built-in prefix routing. For example, you might want to add a supplimental pgweb
database container and instead of running it on `pgweb.myapp.com` you can use a special
path `myapp.com/_pgweb`. Another great example is to run multiple versions of API service
on the same domain like `myapp.com/api/v1' alongside `myapp.com/api/v2'.

To enable to prefix routing, add the following label to docker container:

```bash
docker run \
  --label router.domain=myapp.com \
  --label router.prefix=/api/v1 \ # <-- matching over /api/v1 prefix
  myapp
```

### Healthchecks

By default docker-router will add the container to the internal routing map as soon
as it detects it's start. The new target will be available for routing immediately which
could result in clients getting 502 bad gateway error. Usually it takes a few seconds
for the application to be fully available before servicing any requests, and to
address that docker-router provides a healthcheck feature. To enable it, add the 
following label to your containers when you start them:

```bash
docker run \
  --label router.domain=myapp.com \
  --label router.healthcheck=/health \
  myapp
```

### Websocket Support

Available out of the box with no additional configuration required.

### Idle/Wakeup

If you'd like to put containers to sleep after certain idle time, add the following
label to your container:

```
docker run \
  .... 
  --label=router.domain=myawesomeapp.com \
  --label=router.idletime=30m \
  ...
```