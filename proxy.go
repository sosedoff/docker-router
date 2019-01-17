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
	routes   map[string]map[string]*Route
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

func (p *Proxy) lookup(req *http.Request) *Target {
	host := strings.Split(strings.ToLower(req.Host), ":")[0]
	path := req.URL.Path

	// Find the routing table for the requested hostname
	routeTable, ok := p.routes[host]
	if !ok {
		return nil
	}

	var route *Route

	for prefix, r := range routeTable {
		// Skip catch-all destinations
		if prefix == "" || prefix == "*" {
			continue
		}

		// Find the first matching route
		if strings.HasPrefix(path, prefix) {
			route = r
			break
		}
	}

	// Fallback to the default route if we did not match any with prefix
	if route == nil {
		route = routeTable["*"]
		if route == nil {
			return nil
		}
	}

	return route.pickRoundRobinTarget()
}

func (p *Proxy) addTarget(id, host, prefix, endpoint string) error {
	// Check if domain-level route exists
	_, routeTableExists := p.routes[host]
	p.mapping[id] = fmt.Sprintf("%s@%s", host, prefix)

	// Domain-level routing table does not exist
	if !routeTableExists {
		rt := newRoute()
		rt.addTarget(id, endpoint)
		p.routes[host] = map[string]*Route{prefix: rt}
		return nil
	}

	// Prefix-level routing table does not exist
	_, prefixExists := p.routes[host][prefix]
	if !prefixExists {
		rt := newRoute()
		rt.addTarget(id, endpoint)
		p.routes[host][prefix] = rt
		return nil
	}

	// Find out if the target already exists
	for _, t := range p.routes[host][prefix].Targets {
		if t.Endpoint == endpoint {
			return nil
		}
	}

	// Add the target
	return p.routes[host][prefix].addTarget(id, endpoint)
}

func (p *Proxy) removeTarget(id string) error {
	name, ok := p.mapping[id]
	if !ok {
		return nil
	}
	defer delete(p.mapping, id)

	mapping := strings.Split(name, "@")
	hostName := mapping[0]
	prefixName := mapping[1]

	// Find domain-level entry
	_, ok = p.routes[hostName]
	if !ok {
		return nil
	}

	// Find prefix-level entry
	route, ok := p.routes[hostName][prefixName]
	if !ok {
		return nil
	}

	// Delete the target from the route
	if err := route.deleteTarget(id); err != nil {
		return err
	}

	// Remove the route if it does not have any targets
	if len(route.Targets) == 0 {
		delete(p.routes[hostName], prefixName)
	}

	// Remove the routeTable if it does not have any prefixes
	if len(p.routes[hostName]) == 0 {
		delete(p.routes, hostName)
	}

	return nil
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

	target := proxy.lookup(req)
	if target == nil {
		rl.Status = http.StatusServiceUnavailable
		writeRouteNotFound(rw, rl)
		return
	}

	rl.Destination = target.Endpoint

	req.URL.Scheme = "http"
	req.URL.Host = target.Endpoint

	// configure HSTS
	rw.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")

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
		routes:   map[string]map[string]*Route{},
		mapping:  map[string]string{},
		forceSSL: os.Getenv("FORCE_SSL") == "1" || os.Getenv("FORCE_SSL") == "true",
	}

	return proxy
}

func (proxy *Proxy) hostPolicy() autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		log.Println("host policy request for:", host)
		if _, ok := proxy.routes[host]; !ok {
			log.Println("host policy rejected")
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
			data, _ := json.Marshal(map[string]interface{}{
				"routes":  proxy.routes,
				"mapping": proxy.mapping,
			})
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
			MinVersion:               tls.VersionTLS11,
			PreferServerCipherSuites: true,
		},
	}

	go func() {
		certHandler := certManager.HTTPHandler(handler)
		if err := http.ListenAndServe(":"+httpPort, certHandler); err != nil {
			log.Fatal(err)
		}
	}()

	if os.Getenv("DISABLE_SSL") == "" {
		go func() {
			if err := server.ListenAndServeTLS("", ""); err != nil {
				log.Fatal(err)
			}
		}()
	}

	select {}
}
