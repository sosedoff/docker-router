package main

import (
	"sync"
	"sync/atomic"
	"time"
)

// BasicAuth contains basic authentication credentials
type BasicAuth struct {
	Username string
	Password string
}

func (auth BasicAuth) IsValid(user, password string) bool {
	return auth.Username == user && auth.Password == password
}

type Target struct {
	ID       string
	Endpoint string
	Count    uint64
	Conns    uint64
	Auth     *BasicAuth
}

type Route struct {
	Targets     []*Target
	targetsLock *sync.Mutex
	Total       uint64
}

func newRoute() *Route {
	return &Route{
		Targets:     []*Target{},
		targetsLock: &sync.Mutex{},
		Total:       0,
	}
}

func (r *Route) pickRandomTarget() *Target {
	return r.Targets[randIntn(len(r.Targets))]
}

func (r *Route) pickRoundRobinTarget() *Target {
	u := r.Targets[r.Total%uint64(len(r.Targets))]
	atomic.AddUint64(&r.Total, 1)
	return u
}

func (r *Route) pickLeastConnTarget() *Target {
	return nil
}

func (r *Route) addTarget(id string, endpoint string) (*Target, error) {
	r.targetsLock.Lock()
	defer r.targetsLock.Unlock()

	for _, t := range r.Targets {
		// We don't need duplicate targets
		if t.ID == id || t.Endpoint == endpoint {
			return t, nil
		}
	}

	target := &Target{ID: id, Endpoint: endpoint}
	r.Targets = append(r.Targets, target)

	return target, nil
}

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
