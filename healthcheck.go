package main

import (
	"log"
	"net/http"
	"time"
)

type healthcheck struct {
	endpoint string
	attempts int
	delay    time.Duration
}

func newHealthcheck(endpoint string) *healthcheck {
	return &healthcheck{
		endpoint: endpoint,
		attempts: 10,
		delay:    time.Second,
	}
}

func (h *healthcheck) perform() bool {
	log.Println("starting healthcheck for", h.endpoint)

	for i := 1; i <= h.attempts; i++ {
		resp, err := http.Get(h.endpoint)
		if err != nil {
			log.Printf("[%d/%d] healthcheck failed for %s: %s\n", i, h.attempts, h.endpoint, err)
			time.Sleep(h.delay)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("[%d/%d] healthcheck failed for %s: responded with %v\n", i, h.attempts, h.endpoint, resp.StatusCode)
			time.Sleep(h.delay)
		}

		log.Printf("[%d/%d] healthcheck passed for %s", i, h.attempts, h.endpoint)
		return true
	}

	log.Println("all healthchecks failed for", h.endpoint)
	return false
}
