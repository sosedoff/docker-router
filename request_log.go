package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/satori/go.uuid"
)

type requestLog struct {
	ID          string
	Source      string
	Scheme      string
	Method      string
	Host        string
	Path        string
	Destination string
	Status      int
	Duration    float64
	Time        time.Time
	Agent       string
}

func (l *requestLog) String() string {
	return fmt.Sprintf(
		`id=%q src=%q host=%q scheme=%q method=%q path=%q agent=%q destination=%q status="%v" duration="%v" time=%q`,
		l.ID,
		l.Source,
		l.Host,
		l.Scheme,
		l.Method,
		l.Path,
		l.Agent,
		l.Destination,
		l.Status,
		l.Duration,
		l.Time.Format(time.RFC3339Nano),
	)
}

func (l *requestLog) JSON() string {
	data, err := json.Marshal(l)
	if err != nil {
		log.Println("cant marshal request log:", err)
		return ""
	}
	return string(data)
}

func NewRequestLog(r *http.Request) *requestLog {
	id := r.Header.Get("x-request-id")
	if id == "" {
		id = uuid.NewV4().String()
	}

	return &requestLog{
		ID:     id,
		Source: getRemoteAddr(r),
		Host:   r.Host,
		Method: r.Method,
		Scheme: getRequestScheme(r),
		Path:   r.URL.Path,
		Agent:  r.Header.Get("user-agent"),
		Time:   time.Now().UTC(),
	}
}
