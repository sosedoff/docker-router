package main

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/api/types/events"
	"github.com/docker/docker/client"
)

type Monitor struct {
	api                   *client.Client
	proxy                 *Proxy
	routeLabel            string
	routeNetwork          string
	routePrefixLabel      string
	routeHealthcheckLabel string
	routePort             string
	events                chan RouteEvent
}

type RouteEvent struct {
	ID       string
	Action   string
	Host     string
	Endpoint string
}

func newMonitor(proxy *Proxy) *Monitor {
	c, err := client.NewEnvClient()
	if err != nil {
		log.Fatal(err)
	}

	return &Monitor{
		api:                   c,
		routeLabel:            "router.domain",
		routePrefixLabel:      "router.prefix",
		routeHealthcheckLabel: "router.healthcheck",
		routePort:             "router.port",
		routeNetwork:          "app",
		events:                make(chan RouteEvent),
		proxy:                 proxy,
	}
}

func (m *Monitor) inspectContainer(id string) error {
	log.Println("inspecting container", id)
	c, err := m.api.ContainerInspect(context.Background(), id)
	if err != nil {
		return err
	}

	// Skip if the container is not currently running
	if !c.State.Running {
		log.Println("container", id, "is not running, skipping")
		return nil
	}

	// Skip if container does not have a route label
	host := c.Config.Labels[m.routeLabel]
	if host == "" {
		log.Println("container", id, "does not have label:", m.routeLabel)
		return nil
	}

	// Get the URL prefix
	prefix := c.Config.Labels[m.routePrefixLabel]
	if prefix == "" {
		prefix = "*"
	}

	// Fetch container IP on the network
	net := c.NetworkSettings.Networks[m.routeNetwork]
	if net == nil {
		log.Println("container", id, "does not have network", m.routeNetwork)
		return nil
	}

	ip := net.IPAddress
	port := ""

	if val, ok := c.Config.Labels[m.routePort]; ok {
		port = val
	}

	if port == "" {
		for k := range c.NetworkSettings.Ports {
			port = k.Port()
			break
		}
	}

	if port == "" {
		log.Println("container", id, "does not have any exposed ports")
		return nil
	}

	// Check if we can actually add the endpoint
	if healthEndpoint := c.Config.Labels[m.routeHealthcheckLabel]; healthEndpoint != "" {
		check := newHealthcheck(fmt.Sprintf("http://%v:%v%s", ip, port, healthEndpoint))
		if available := check.perform(); !available {
			return fmt.Errorf("healthcheck failed")
		}
	} else {
		log.Println("container", id, "does not have healthcheck endpoint")
	}

	return m.proxy.addTarget(id, host, prefix, fmt.Sprintf("%v:%v", ip, port))
}

func (m *Monitor) removeContainer(id string) {
	log.Println("removing container", id)
	m.proxy.removeTarget(id)
}

func (m *Monitor) inspectExistingContainers() {
	list, err := m.api.ContainerList(context.Background(), types.ContainerListOptions{})
	if err != nil {
		log.Println("cant list containers:", err)
		return
	}

	wg := &sync.WaitGroup{}
	wg.Add(len(list))

	for _, c := range list {
		go func(id string) {
			m.inspectContainer(id)
			wg.Done()
		}(c.ID)
	}

	wg.Wait()
}

func (m *Monitor) handleEvent(e events.Message) {
	switch e.Action {
	case "start":
		m.inspectContainer(e.ID)
	case "kill", "die", "stop", "destroy":
		m.removeContainer(e.ID)
	}
}

func (m *Monitor) start() {
	m.inspectExistingContainers()

	messages, errors := m.api.Events(context.Background(), types.EventsOptions{})

	for {
		select {
		case event := <-messages:
			if event.Type == "container" {
				go m.handleEvent(event)
			}
		case err := <-errors:
			if err != nil {
				log.Println("error:", err)
			}
			time.Sleep(time.Second)
		}
	}
}
