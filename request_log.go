package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	uuid "github.com/satori/go.uuid"
)

type requestLog struct {
	ID          string            `json:"id"`
	Source      string            `json:"src"`
	Destination string            `json:"dst"`
	Scheme      string            `json:"scheme"`
	Method      string            `json:"method"`
	Host        string            `json:"host"`
	Path        string            `json:"path"`
	Status      int               `json:"status"`
	Duration    float64           `json:"duration"`
	Time        time.Time         `json:"time"`
	Agent       string            `json:"agent"`
	Meta        map[string]string `json:"meta"`
}

func (l *requestLog) String() string {
	meta := make([]string, len(l.Meta))
	i := 0
	for k, v := range l.Meta {
		meta[i] = fmt.Sprintf("%s=%s", k, v)
		i++
	}

	return fmt.Sprintf(
		`id=%q src=%q host=%q scheme=%q method=%q path=%q agent=%q destination=%q status="%v" duration="%v" meta=%q time=%q`,
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
		strings.Join(meta, ","),
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

func newRequestLog(r *http.Request) *requestLog {
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
		Meta:   map[string]string{},
	}
}
