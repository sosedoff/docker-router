build:
	go build

docker:
	GOOS=linux GOARCH=amd64 go build -o docker-router-linux
	docker build -t sosedoff/beam .

docker-push:
	docker push sosedoff/beam