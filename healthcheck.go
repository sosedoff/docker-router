package main

import (
	"io/ioutil"
	"log"
	"net/http"
	"time"
)

type healthcheck struct {
	endpoint string
	attempts int
	delay    time.Duration
}

func performHealthCheck(destination string) bool {
	endpoint := "http://" + destination
	attempts := 10
	delay := time.Second

	for {
		attempts -= 1
		if attempts < 0 {
			log.Println("all attempts for", destination, "are exhausted")
			return false
		}

		resp, err := http.Get(endpoint)
		if err != nil {
			log.Println("healthcheck for", destination, "failed. error:", err)
			time.Sleep(delay)
			continue
		}
		ioutil.ReadAll(resp.Body)
		resp.Body.Close()
		break
	}

	return true
}
