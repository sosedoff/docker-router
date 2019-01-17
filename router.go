package main

import (
	"sync"
	"sync/atomic"
	"time"
)

type Target struct {
	ID       string
	Endpoint string
	Count    uint64
	Conns    uint64
}

type Route struct {
	Targets     []*Target
	targetsLock *sync.Mutex
	Total       uint64
}

// Instantiate a new route
func newRoute() *Route {
	return &Route{
		Targets:     []*Target{},
		targetsLock: &sync.Mutex{},
		Total:       0,
	}
}

// Pick a random route target
func (r *Route) pickRandomTarget() *Target {
	return r.Targets[randIntn(len(r.Targets))]
}

// Pick a route target using round robin method
func (r *Route) pickRoundRobinTarget() *Target {
	u := r.Targets[r.Total%uint64(len(r.Targets))]
	atomic.AddUint64(&r.Total, 1)
	return u
}

// Pick a route target using least connections method
func (r *Route) pickLeastConnTarget() *Target {
	return nil
}

// Add a new target to the route
func (r *Route) addTarget(id string, endpoint string) error {
	r.targetsLock.Lock()
	defer r.targetsLock.Unlock()

	for _, t := range r.Targets {
		// We don't need duplicate targets
		if t.ID == id || t.Endpoint == endpoint {
			return nil
		}
	}

	r.Targets = append(r.Targets, &Target{ID: id, Endpoint: endpoint})
	return nil
}

// Delete an existing target by ID
func (r *Route) deleteTarget(id string) error {
	r.targetsLock.Lock()
	defer r.targetsLock.Unlock()

	targets := []*Target{}
	for _, t := range r.Targets {
		if t.ID != id {
			targets = append(targets, t)
		}
	}
	r.Targets = targets
	return nil
}

func randIntn(n int) int {
	if n == 0 {
		return 0
	}
	return int(time.Now().UnixNano()/int64(time.Microsecond)) % n
}
