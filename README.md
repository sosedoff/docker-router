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

### Debugging

To see the internal routing state and table, add `DEBUG=1` env var when starting `docker-proxy`.

You should be able to open `http://router-hostname/_routes` endpoint.

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
        "Targets": [
          {
            "ID": "751d7b4a32a02cd56d8f1009d490e2d3b13d62da3b2a90ea609563e63ea69398",
            "Endpoint": "172.20.0.3:5000",
            "Count": 0,
            "Conns": 0
          },
          {
            "ID": "41a2b6cfaf5822d743a6ae0a178d1b3cd32e5534d274310e75eb21fc68eaa5e4",
            "Endpoint": "172.20.0.4:5000",
            "Count": 0,
            "Conns": 0
          },
          {
            "ID": "518a0dc6ca67837954f08c20ad2dec48904b508728d456eeeba7bafab8f88cab",
            "Endpoint": "172.20.0.5:5000",
            "Count": 0,
            "Conns": 0
          }
        ],
        "Total": 24
      }
    }
  }
}
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