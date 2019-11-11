build:
	go build

docker:
	docker build -t sosedoff/docker-router .

docker-push:
	docker push sosedoff/docker-router

docker-release: docker docker-push