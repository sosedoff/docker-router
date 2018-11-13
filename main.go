package main

import (
	"math/rand"
	"time"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	proxy := newProxy()
	monitor := newMonitor(proxy)

	go monitor.start()
	proxy.start()
}
