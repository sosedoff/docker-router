package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

type Proxy struct {
	proxy    *httputil.ReverseProxy
	mapping  map[string]string
	routes   map[string]*Route
	forceSSL bool
}

func getTargetHost(val string) string {
	return strings.Split(val, ":")[0]
}

func getRouteHost(val string) string {
	return strings.Split(val, ":")[0]
}

func getRemoteAddr(r *http.Request) string {
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func getRequestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func writeRouteNotFound(rw http.ResponseWriter, rl *requestLog) {
	rw.WriteHeader(rl.Status)
}

// Find a route target for the given hostname
func (p *Proxy) lookup(host string) *Target {
	route, ok := p.routes[host]
	if !ok {
		return nil
	}
	return route.pickRoundRobinTarget()
}

func (p *Proxy) addTarget(id string, host string, endpoint string) error {
	route, ok := p.routes[host]
	p.mapping[id] = host

	if !ok {
		rt := newRoute()
		rt.addTarget(id, endpoint)
		p.routes[host] = rt
		return nil
	}

	for _, t := range route.Targets {
		if t.Endpoint == endpoint {
			return nil
		}
	}

	return route.addTarget(id, endpoint)
}

func (p *Proxy) removeTarget(id string) error {
	host, ok := p.mapping[id]
	if !ok {
		return nil
	}

	route, ok := p.routes[host]
	if !ok {
		return nil
	}

	return route.deleteTarget(id)
}

func (proxy *Proxy) handleRequest(rw http.ResponseWriter, req *http.Request) {
	wrapRw := &responseWriter{w: rw}

	rl := NewRequestLog(req)
	defer func() {
		log.Println(rl.String())
	}()

	// Issue a redirect from http -> https
	if proxy.forceSSL && rl.Scheme == "http" {
		requestURL := &url.URL{
			Scheme:   "https",
			Host:     rl.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}

		http.Redirect(rw, req, requestURL.String(), 301)
		return
	}

	target := proxy.lookup(getRouteHost(req.Host))
	if target == nil {
		rl.Status = http.StatusServiceUnavailable
		writeRouteNotFound(rw, rl)
		return
	}

	rl.Destination = target.Endpoint

	req.URL.Scheme = "http"
	req.URL.Host = target.Endpoint

	ts := time.Now()
	proxy.proxy.ServeHTTP(wrapRw, req)

	rl.Duration = time.Since(ts).Seconds()
	rl.Status = wrapRw.code
}

func newProxy() *Proxy {
	reverseProxy := httputil.NewSingleHostReverseProxy(&url.URL{})
	reverseProxy.Director = func(req *http.Request) {
		req.Header.Set("X-Forwarded-Host", req.Host)
		req.Header.Set("X-Forwarded-For", req.RemoteAddr)
		req.Header.Set("X-Forwarded-Proto", getRequestScheme(req))

		// explicitly disable User-Agent so it's not set to default value
		if _, ok := req.Header["User-Agent"]; !ok {
			req.Header.Set("User-Agent", "")
		}
	}

	proxy := &Proxy{
		proxy:    reverseProxy,
		routes:   map[string]*Route{},
		mapping:  map[string]string{},
		forceSSL: os.Getenv("FORCE_SSL") == "1" || os.Getenv("FORCE_SSL") == "true",
	}

	return proxy
}

func (proxy *Proxy) hostPolicy() autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		log.Println("host-pocity request for:", host)
		if _, ok := proxy.routes[host]; !ok {
			log.Println("host-policy rejected")
			return errors.New("invalid host")
		}
		return nil
	}
}

func (proxy *Proxy) start() {
	httpPort := os.Getenv("HTTP_PORT")
	if httpPort == "" {
		httpPort = "8080"
	}

	httpsPort := os.Getenv("HTTPS_PORT")
	if httpsPort == "" {
		httpsPort = "8443"
	}

	certManager, err := configureCertManager(proxy.hostPolicy())
	if err != nil {
		log.Fatal(err)
	}

	handler := http.NewServeMux()
	handler.HandleFunc("/", proxy.handleRequest)

	// Debug routes
	if os.Getenv("DEBUG") != "" {
		handler.HandleFunc("/_test", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(rw, "test\n")
		})

		handler.HandleFunc("/_routes", func(rw http.ResponseWriter, r *http.Request) {
			data, _ := json.Marshal(proxy.routes)
			fmt.Fprintf(rw, "%s\n", data)
		})
	}

	server := &http.Server{
		Addr:    ":" + httpsPort,
		Handler: handler,
		TLSConfig: &tls.Config{
			GetCertificate: certManager.GetCertificate,
			CipherSuites: []uint16{
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
				tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
				tls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
				tls.TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA,
			},
		},
	}

	go func() {
		certHandler := certManager.HTTPHandler(handler)
		if err := http.ListenAndServe(":"+httpPort, certHandler); err != nil {
			log.Fatal(err)
		}
	}()

	go func() {
		if err := server.ListenAndServeTLS("", ""); err != nil {
			log.Fatal(err)
		}
	}()

	select {}
}
