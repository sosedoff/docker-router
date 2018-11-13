build:
	go build

docker:
	GOOS=linux GOARCH=amd64 go build
	docker build -t sosedoff/beam .