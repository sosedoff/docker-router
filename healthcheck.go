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

	attempt := 0

	for {
		attempt++

		if attempt > h.attempts {
			log.Println("all healthchecks failed for", h.endpoint)
			return false
		}

		resp, err := http.Get(h.endpoint)
		if err != nil {
			log.Printf("[%d/%d] healthcheck failed for %s: %s\n", attempt, h.attempts, h.endpoint, err)
			time.Sleep(h.delay)
			continue
		}
		resp.Body.Close()

		if resp.StatusCode != 200 {
			log.Printf("[%d/%d] healthcheck failed for %s: responded with %v\n", attempt, h.attempts, h.endpoint, resp.StatusCode)
			time.Sleep(h.delay)
		}

		break
	}

	log.Printf("[%d/%d] healthcheck passed for %s", attempt, h.attempts, h.endpoint)
	return true
}
