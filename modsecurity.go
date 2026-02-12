// Package traefik_modsecurity_plugin a modsecurity plugin.
package traefik_modsecurity_plugin

import (
	"bytes"
	"context"
	"crypto/tls"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"os"
	"slices"
	"sync"
	"time"
)

// Defaults.
var (
	defaultServiceURL           = "http://modsec:8080"
	defaultTimeout              = 2 * time.Second
	defaultDialTimeout          = 30 * time.Second
	defaultIdleTimeout          = 90 * time.Second
	defaultJailEnabled          = false
	defaultJailBadRequestLimit  = 25
	defaultJailBadRequestPeriod = 600 * time.Second
	defaultJailDuration         = 1 * time.Hour
	defaultMaxConns             = 4
	defaultMaxIdleConns         = 2
	defaultBackoff              = 0 * time.Second
)

// Config the plugin configuration.
type Config struct {
	ServiceURL   string        `json:"serviceUrl,omitempty"`
	Timeout      time.Duration `json:"timeout,omitempty"`
	DialTimeout  time.Duration `json:"dialTimeout,omitempty"`
	IdleTimeout  time.Duration `json:"idleTimeout,omitempty"`
	Jail         *JailConfig   `json:"jail,omitempty"`
	MaxConns     int           `json:"maxConns,omitempty"`
	MaxIdleConns int           `json:"maxIdleConns,omitempty"`
	Backoff      time.Duration `json:"backoff,omitempty"`
}

type JailConfig struct {
	Enabled          bool          `json:"enabled,omitempty"`
	BadRequestLimit  int           `json:"badRequestLimit,omitempty"`
	BadRequestPeriod time.Duration `json:"badRequestPeriod,omitempty"`
	Duration         time.Duration `json:"duration,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Timeout:     defaultTimeout,
		DialTimeout: defaultDialTimeout,
		IdleTimeout: defaultIdleTimeout,
		Jail: &JailConfig{
			Enabled:          defaultJailEnabled,
			BadRequestLimit:  defaultJailBadRequestLimit,
			BadRequestPeriod: defaultJailBadRequestPeriod,
			Duration:         defaultJailDuration,
		},
		MaxConns:     defaultMaxConns,
		MaxIdleConns: defaultMaxIdleConns,
		Backoff:      defaultBackoff,
	}
}

// Modsecurity a Modsecurity plugin.
type Modsecurity struct {
	next        http.Handler
	serviceURL  string
	name        string
	cl          *http.Client
	l           *log.Logger
	jail        JailConfig
	backoff     time.Duration
	jailMap     map[string][]time.Time
	jailRelease map[string]time.Time
	unhealthy   bool
	unhealthyMu sync.Mutex
	rw          sync.RWMutex
}

// New creates a new Modsecurity plugin with the given configuration.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	dialer := &net.Dialer{
		Timeout:   cfg.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return &Modsecurity{
		serviceURL: cfg.ServiceURL,
		next:       next,
		name:       name,
		cl: &http.Client{
			Timeout: cfg.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxConnsPerHost:       cfg.MaxConns,
				MaxIdleConnsPerHost:   cfg.MaxIdleConns,
				IdleConnTimeout:       cfg.IdleTimeout,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ForceAttemptHTTP2: true,
				DialContext:       dialer.DialContext,
			},
		},
		l:           log.New(os.Stdout, "", log.LstdFlags),
		jail:        *cfg.Jail,
		backoff:     cfg.Backoff,
		jailMap:     make(map[string][]time.Time),
		jailRelease: make(map[string]time.Time),
	}, nil
}

func (m *Modsecurity) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	if isWebsocket(req) {
		m.next.ServeHTTP(w, req)
		return
	}
	ip := req.RemoteAddr
	// jail check
	if m.jail.Enabled {
		m.rw.RLock()
		if m.isJailed(ip) {
			m.rw.RUnlock()
			m.l.Printf("client %q is jailed", ip)
			http.Error(w, http.StatusText(http.StatusForbidden), http.StatusForbidden)
			return
		}
		m.rw.RUnlock()
	}
	// breaker check
	if m.unhealthy {
		m.next.ServeHTTP(w, req)
		return
	}
	// buffer body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		m.l.Printf("fail to read incoming request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	req.Body = io.NopCloser(bytes.NewReader(body))
	proxyReq, err := http.NewRequest(req.Method, m.serviceURL+req.RequestURI, bytes.NewReader(body))
	if err != nil {
		m.l.Printf("fail to prepare forwarded request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	maps.Copy(proxyReq.Header, req.Header)
	res, err := m.cl.Do(proxyReq)
	if err != nil {
		m.markUnhealthy()
		m.next.ServeHTTP(w, req)
		return
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 {
		m.markUnhealthy()
	}
	if res.StatusCode >= 400 {
		if res.StatusCode == http.StatusForbidden && m.jail.Enabled {
			m.recordOffense(ip)
		}
		forward(w, res)
		return
	}
	m.next.ServeHTTP(w, req)
}

// markUnhealthy toggles the breaker for the configured back-off window.
func (m *Modsecurity) markUnhealthy() {
	if m.backoff == 0 {
		return
	}
	m.unhealthyMu.Lock()
	if !m.unhealthy {
		m.unhealthy = true
		back := m.backoff
		m.l.Printf("marking modsec as unhealthy for %v", back)
		time.AfterFunc(time.Duration(back)*time.Second, func() {
			m.unhealthyMu.Lock()
			m.unhealthy = false
			m.unhealthyMu.Unlock()
			m.l.Printf("modsec unhealthy backoff expired")
		})
	}
	m.unhealthyMu.Unlock()
}

func isWebsocket(req *http.Request) bool {
	return slices.Contains(req.Header["Upgrade"], "websocket")
}

func forward(w http.ResponseWriter, res *http.Response) {
	for k, h := range res.Header {
		for _, v := range h {
			w.Header().Add(k, v)
		}
	}
	w.WriteHeader(res.StatusCode)
	io.Copy(w, res.Body)
}

func (m *Modsecurity) recordOffense(ip string) {
	m.rw.Lock()
	defer m.rw.Unlock()
	now := time.Now()
	// remove offenses that are older than the threshold period
	if offenses, exists := m.jailMap[ip]; exists {
		var newOffenses []time.Time
		for _, offense := range offenses {
			if now.Sub(offense) <= m.jail.BadRequestPeriod {
				newOffenses = append(newOffenses, offense)
			}
		}
		m.jailMap[ip] = newOffenses
	}
	// record the new offense
	m.jailMap[ip] = append(m.jailMap[ip], now)
	// check if the client should be jailed
	if len(m.jailMap[ip]) >= m.jail.BadRequestLimit {
		m.l.Printf("client %q reached bad request threshold (%d), jailing", ip, m.jail.BadRequestLimit)
		m.jailRelease[ip] = now.Add(m.jail.Duration)
	}
}

func (m *Modsecurity) isJailed(ip string) bool {
	if t, exists := m.jailRelease[ip]; exists {
		if time.Now().Before(t) {
			return true
		}
		m.release(ip)
	}
	return false
}

func (m *Modsecurity) release(ip string) {
	m.rw.Lock()
	defer m.rw.Unlock()
	delete(m.jailMap, ip)
	delete(m.jailRelease, ip)
	m.l.Printf("client %q released from jail", ip)
}
