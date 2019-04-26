# docker-router

Routing proxy for Docker containers with native LetsEncrypt support

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