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

// IsValid returns true if provided username and password matches
func (auth BasicAuth) IsValid(user, password string) bool {
	return auth.Username == user && auth.Password == password
}

// Target contains backend endpoint and metadata
type Target struct {
	ID       string     `json:"id"`
	Endpoint string     `json:"endpoint"`
	Count    uint64     `json:"count"`
	Conns    uint64     `json:"conns"`
	Auth     *BasicAuth `json:"-"`
}

// Route contains route destinations
type Route struct {
	Targets []*Target `json:"targetrs"`
	Total   uint64    `json:"total"`

	targetsLock *sync.Mutex
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
