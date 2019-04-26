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
  -e LETSENCRYPT_EMAIL=...YOUR EMAIL... \
  -e LETSENCRYPT_CERTS_DIR=/certs \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v /root/certs:/certs \
  sosedoff/docker-router
```