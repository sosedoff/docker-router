package main

import (
	"flag"
	"log"
	"math/rand"
	"time"

	"github.com/sosedoff/docker-router/config"
	"github.com/sosedoff/docker-router/oauth"
)

func init() {
	rand.Seed(time.Now().UTC().UnixNano())
}

func main() {
	var configPath string

	flag.StringVar(&configPath, "config", "", "Path to config file")
	flag.Parse()

	proxy := newProxy()
	monitor := newMonitor(proxy)

	if configPath != "" {
		serverConfig, err := config.Load(configPath)
		if err != nil {
			log.Fatal(err)
		}

		handlers, err := oauth.Init(serverConfig)
		if err != nil {
			log.Fatal(err)
		} else {
			proxy.oauthHandlers = handlers
		}
	}

	go monitor.start()
	proxy.start()
}
