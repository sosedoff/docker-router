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
	"sync"
	"time"

	"github.com/docker/docker/api/types"
	"github.com/docker/docker/client"
	"golang.org/x/crypto/acme/autocert"
)

const (
	// Allowed HTTP methods
	allowedMethods = "OPTIONS HEAD GET POST PUT PATCH DELETE CONNECT UPGRADE TRACE"

	// Default docker network to connect to
	defaultNetworkname = "app"
)

type Proxy struct {
	proxy       *httputil.ReverseProxy
	mapping     map[string]string
	accessTime  map[string]time.Time
	routes      map[string]map[string]*Route
	forceSSL    bool
	networkName string
	api         *client.Client
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

func writeInvalidAuth(rw http.ResponseWriter, rl *requestLog) {
	rl.Status = http.StatusUnauthorized
	rw.Header().Set("WWW-Authenticate", `Basic realm="Restricted"`)
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

func (p *Proxy) addTarget(id, host, prefix, endpoint string) (*Target, error) {
	// Check if domain-level route exists
	_, routeTableExists := p.routes[host]
	p.mapping[id] = fmt.Sprintf("%s@%s", host, prefix)

	// Domain-level routing table does not exist
	if !routeTableExists {
		rt := newRoute()

		target, err := rt.addTarget(id, endpoint)
		if err != nil {
			return nil, err
		}

		p.accessTime[id] = time.Now()
		p.routes[host] = map[string]*Route{prefix: rt}

		return target, nil
	}

	// Prefix-level routing table does not exist
	_, prefixExists := p.routes[host][prefix]
	if !prefixExists {
		rt := newRoute()

		target, err := rt.addTarget(id, endpoint)
		if err != nil {
			return nil, err
		}

		p.routes[host][prefix] = rt
		p.accessTime[id] = time.Now()

		return target, nil
	}

	// Find out if the target already exists
	for _, t := range p.routes[host][prefix].Targets {
		if t.Endpoint == endpoint {
			return t, nil
		}
	}

	// Add the target
	p.accessTime[id] = time.Now()
	return p.routes[host][prefix].addTarget(id, endpoint)
}

func (p *Proxy) removeTarget(id string) error {
	name, ok := p.mapping[id]
	if !ok {
		return nil
	}
	defer func() {
		delete(p.mapping, id)
		delete(p.accessTime, id)
	}()

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

// isValidMethod returns true if given HTTP methid is valid
func (proxy *Proxy) isValidMethod(method string) bool {
	return strings.Index(allowedMethods, method) >= 0
}

// startIdleContainersForHost starts any existing stopped containers
func (proxy *Proxy) startIdleContainersForHost(host string) error {
	list, err := proxy.api.ContainerList(context.Background(), types.ContainerListOptions{All: true})
	if err != nil {
		log.Println("can fetch container list:", err)
		return err
	}

	idsToStart := []string{}
	for _, c := range list {
		if c.State != "exited" {
			continue
		}
		if c.Labels["router.idletime"] == "" {
			continue
		}
		if c.Labels["router.domain"] != host {
			continue
		}
		idsToStart = append(idsToStart, c.ID)
	}

	wg := &sync.WaitGroup{}
	wg.Add(len(idsToStart))

	for _, id := range idsToStart {
		go func(cid string) {
			defer wg.Done()

			log.Println("starting stopped container", cid, "for host", host)

			restartTimeout := time.Second * 10
			if err := proxy.api.ContainerRestart(context.Background(), cid, &restartTimeout); err != nil {
				log.Println("failed to start container:", err)
				return
			}

			for i := 0; i < 10; i++ {
				log.Println("waiting for container", cid, "to register for", host)
				if proxy.mapping[cid] == host {
					return
				}
				time.Sleep(time.Second)
			}
		}(id)
	}

	wg.Wait()
	return nil
}

func (proxy *Proxy) handleRequest(rw http.ResponseWriter, req *http.Request) {
	wrapRw := &responseWriter{w: rw}

	req.Host = strings.ToLower(req.Host)
	req.Method = strings.ToUpper(req.Method)

	rl := NewRequestLog(req)
	defer func() {
		log.Println(rl.String())
	}()

	// Check if request method is correct
	if !proxy.isValidMethod(req.Method) {
		wrapRw.WriteHeader(http.StatusMethodNotAllowed)
		return
	}

	// Issue a redirect from http -> https
	if proxy.forceSSL && rl.Scheme == "http" {
		requestURL := &url.URL{
			Scheme:   "https",
			Host:     rl.Host,
			Path:     req.URL.Path,
			RawQuery: req.URL.RawQuery,
		}

		http.Redirect(wrapRw, req, requestURL.String(), 301)
		return
	}

	target := proxy.lookup(req)

	// Try to start the stopped containers that have host label
	if target == nil {
		host := strings.Split(strings.ToLower(req.Host), ":")[0]
		if err := proxy.startIdleContainersForHost(host); err == nil {
			target = proxy.lookup(req)
		}
	}
	if target == nil {
		rl.Status = http.StatusServiceUnavailable
		writeRouteNotFound(wrapRw, rl)
		return
	}

	// Verify authentication
	if target.Auth != nil {
		user, pass, ok := req.BasicAuth()
		if ok {
			ok = target.Auth.IsValid(user, pass)
		}
		if !ok {
			writeInvalidAuth(wrapRw, rl)
			return
		}
	}

	// Set last access time for the target
	proxy.accessTime[target.ID] = time.Now().UTC()

	rl.Destination = target.Endpoint

	req.URL.Scheme = "http"
	req.URL.Host = target.Endpoint

	ts := time.Now()

	// Handle websocket proxy
	upgrade := req.Header.Get("Upgrade")
	if upgrade == "websocket" || upgrade == "Websocket" {
		proxy.proxy.ServeHTTP(rw, req)
	} else {
		// configure HSTS
		rw.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains")
		proxy.proxy.ServeHTTP(wrapRw, req)
	}

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

	networkName := os.Getenv("DOCKER_NETWORK")
	if networkName == "" {
		networkName = defaultNetworkname
	}

	forceSSL := false
	if val := os.Getenv("FORCE_SSL"); val == "true" || val == "1" {
		forceSSL = true
	}

	dockerApi, err := client.NewEnvClient()
	if err != nil {
		log.Fatal(err)
	}

	proxy := &Proxy{
		proxy:       reverseProxy,
		routes:      map[string]map[string]*Route{},
		mapping:     map[string]string{},
		accessTime:  map[string]time.Time{},
		networkName: networkName,
		forceSSL:    forceSSL,
		api:         dockerApi,
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
		handler.HandleFunc("/_router/test", func(rw http.ResponseWriter, r *http.Request) {
			fmt.Fprintf(rw, "OK\n")
		})

		handler.HandleFunc("/_router/info", func(rw http.ResponseWriter, r *http.Request) {
			data, _ := json.Marshal(map[string]interface{}{
				"routes":     proxy.routes,
				"mapping":    proxy.mapping,
				"accesstime": proxy.accessTime,
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
