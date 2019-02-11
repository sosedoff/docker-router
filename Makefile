build:
	go build

docker:
	docker build -t sosedoff/beam .

docker-push:
	docker push sosedoff/beam