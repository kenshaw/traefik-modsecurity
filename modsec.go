// Package traefik_modsec is a Traefik plugin that proxies requests to a Modsecurity
// service.
package traefik_modsec

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"log"
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

// Config contains the modsec plugin configuration.
type Config struct {
	ServiceURL   string     `json:"serviceUrl,omitempty"`
	Timeout      string     `json:"timeout,omitempty"`
	DialTimeout  string     `json:"dialTimeout,omitempty"`
	IdleTimeout  string     `json:"idleTimeout,omitempty"`
	Jail         JailConfig `json:"jail,omitempty"`
	MaxConns     int        `json:"maxConns,omitempty"`
	MaxIdleConns int        `json:"maxIdleConns,omitempty"`
	Backoff      string     `json:"backoff,omitempty"`
}

type JailConfig struct {
	Enabled          bool   `json:"enabled,omitempty"`
	BadRequestLimit  int    `json:"badRequestLimit,omitempty"`
	BadRequestPeriod string `json:"badRequestPeriod,omitempty"`
	Duration         string `json:"duration,omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		Timeout:     defaultTimeout.String(),
		DialTimeout: defaultDialTimeout.String(),
		IdleTimeout: defaultIdleTimeout.String(),
		Jail: JailConfig{
			Enabled:          defaultJailEnabled,
			BadRequestLimit:  defaultJailBadRequestLimit,
			BadRequestPeriod: defaultJailBadRequestPeriod.String(),
			Duration:         defaultJailDuration.String(),
		},
		MaxConns:     defaultMaxConns,
		MaxIdleConns: defaultMaxIdleConns,
		Backoff:      defaultBackoff.String(),
	}
}

// Modsec provides the traefik modsec plugin.
type Modsec struct {
	next        http.Handler
	serviceURL  string
	name        string
	cl          *http.Client
	l           *log.Logger
	cfg         config
	jailMap     map[string][]time.Time
	jailRelease map[string]time.Time
	unhealthy   bool
	unhealthyMu sync.Mutex
	rw          sync.RWMutex
	once        sync.Once
}

// New creates a new Modsec plugin with the given configuration.
func New(ctx context.Context, next http.Handler, cfg *Config, name string) (http.Handler, error) {
	config, err := parseConfig(cfg)
	if err != nil {
		return nil, err
	}
	dialer := &net.Dialer{
		Timeout:   config.DialTimeout,
		KeepAlive: 30 * time.Second,
	}
	return &Modsec{
		serviceURL: config.ServiceURL,
		next:       next,
		name:       name,
		cl: &http.Client{
			Timeout: config.Timeout,
			Transport: &http.Transport{
				MaxIdleConns:          100,
				MaxConnsPerHost:       config.MaxConns,
				MaxIdleConnsPerHost:   config.MaxIdleConns,
				IdleConnTimeout:       config.IdleTimeout,
				TLSHandshakeTimeout:   10 * time.Second,
				ExpectContinueTimeout: 1 * time.Second,
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				ForceAttemptHTTP2: true,
				DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
					return dialer.DialContext(ctx, network, addr)
				},
			},
		},
		l:           log.New(os.Stdout, "", log.LstdFlags),
		cfg:         config,
		jailMap:     make(map[string][]time.Time),
		jailRelease: make(map[string]time.Time),
	}, nil
}

func (m *Modsec) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	m.once.Do(func() {
		buf, err := json.Marshal(m.cfg)
		if err != nil {
			m.l.Fatalf("unable to marshal config: %v", err)
		}
		m.l.Printf("configuration: %s", string(buf))
	})
	// if websocket
	if slices.Contains(req.Header["Upgrade"], "websocket") {
		m.next.ServeHTTP(w, req)
		return
	}
	ip := req.RemoteAddr
	// check if client is jailed
	if m.cfg.Jail.Enabled {
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
	// m.l.Printf("Sending %s %s -- %q", req.Method, m.serviceURL+req.RequestURI, m.serviceURL)
	proxyReq, err := http.NewRequest(req.Method, m.serviceURL+req.RequestURI, bytes.NewReader(body))
	if err != nil {
		m.l.Printf("fail to prepare forwarded request: %v", err)
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	mapsCopy(proxyReq.Header, req.Header)
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
		if res.StatusCode == http.StatusForbidden && m.cfg.Jail.Enabled {
			m.recordOffense(ip)
		}
		forward(w, res)
		return
	}
	m.next.ServeHTTP(w, req)
}

// markUnhealthy toggles the breaker for the configured back-off window.
func (m *Modsec) markUnhealthy() {
	if m.cfg.Backoff == 0 {
		return
	}
	m.unhealthyMu.Lock()
	if !m.unhealthy {
		m.unhealthy = true
		back := m.cfg.Backoff
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

func (m *Modsec) recordOffense(ip string) {
	m.rw.Lock()
	defer m.rw.Unlock()
	now := time.Now()
	// remove offenses that are older than the threshold period
	if offenses, exists := m.jailMap[ip]; exists {
		var newOffenses []time.Time
		for _, offense := range offenses {
			if now.Sub(offense) <= m.cfg.Jail.BadRequestPeriod {
				newOffenses = append(newOffenses, offense)
			}
		}
		m.jailMap[ip] = newOffenses
	}
	// record the new offense
	m.jailMap[ip] = append(m.jailMap[ip], now)
	// check if the client should be jailed
	if len(m.jailMap[ip]) >= m.cfg.Jail.BadRequestLimit {
		m.l.Printf("client %q reached bad request threshold (%d), jailing", ip, m.cfg.Jail.BadRequestLimit)
		m.jailRelease[ip] = now.Add(m.cfg.Jail.Duration)
	}
}

func (m *Modsec) isJailed(ip string) bool {
	if t, exists := m.jailRelease[ip]; exists {
		if time.Now().Before(t) {
			return true
		}
		m.release(ip)
	}
	return false
}

func (m *Modsec) release(ip string) {
	m.rw.Lock()
	defer m.rw.Unlock()
	delete(m.jailMap, ip)
	delete(m.jailRelease, ip)
	m.l.Printf("client %q released from jail", ip)
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

// config wraps the configuration values.
type config struct {
	ServiceURL   string        `json:"serviceUrl"`
	Timeout      time.Duration `json:"timeout"`
	DialTimeout  time.Duration `json:"dialTimeout"`
	IdleTimeout  time.Duration `json:"idleTimeout"`
	MaxConns     int           `json:"maxConns"`
	MaxIdleConns int           `json:"maxIdleConns"`
	Backoff      time.Duration `json:"backoff"`
	Jail         struct {
		Enabled          bool          `json:"enabled"`
		BadRequestLimit  int           `json:"badRequestLimit"`
		BadRequestPeriod time.Duration `json:"badRequestPeriod"`
		Duration         time.Duration `json:"duration"`
	} `json:"jail"`
}

// parseConfig parses the [Config] into a [config].
func parseConfig(cfg *Config) (config, error) {
	c := config{
		ServiceURL:   defaultServiceURL,
		Timeout:      defaultTimeout,
		DialTimeout:  defaultDialTimeout,
		IdleTimeout:  defaultIdleTimeout,
		MaxConns:     defaultMaxConns,
		MaxIdleConns: defaultMaxIdleConns,
		Backoff:      defaultBackoff,
		Jail: struct {
			Enabled          bool          `json:"enabled"`
			BadRequestLimit  int           `json:"badRequestLimit"`
			BadRequestPeriod time.Duration `json:"badRequestPeriod"`
			Duration         time.Duration `json:"duration"`
		}{
			Enabled:          defaultJailEnabled,
			BadRequestLimit:  defaultJailBadRequestLimit,
			BadRequestPeriod: defaultJailBadRequestPeriod,
			Duration:         defaultJailDuration,
		},
	}
	if cfg.ServiceURL != "" {
		c.ServiceURL = cfg.ServiceURL
	}
	var err error
	if c.Timeout, err = parseDuration(cfg.Timeout, defaultTimeout); err != nil {
		return config{}, fmt.Errorf("invalid timeout: %q: %w", cfg.Timeout, err)
	}
	if c.DialTimeout, err = parseDuration(cfg.DialTimeout, defaultDialTimeout); err != nil {
		return config{}, fmt.Errorf("invalid dial timeout: %q: %w", cfg.DialTimeout, err)
	}
	if c.IdleTimeout, err = parseDuration(cfg.IdleTimeout, defaultIdleTimeout); err != nil {
		return config{}, fmt.Errorf("invalid idle timeout: %q: %w", cfg.IdleTimeout, err)
	}
	if cfg.MaxConns != 0 {
		c.MaxConns = cfg.MaxConns
	}
	if cfg.MaxIdleConns != 0 {
		c.MaxIdleConns = cfg.MaxIdleConns
	}
	if c.Backoff, err = parseDuration(cfg.Backoff, defaultBackoff); err != nil {
		return config{}, fmt.Errorf("invalid backoff: %q: %w", cfg.Backoff, err)
	}
	c.Jail.Enabled = cfg.Jail.Enabled
	if cfg.Jail.BadRequestLimit != 0 {
		c.Jail.BadRequestLimit = cfg.Jail.BadRequestLimit
	}
	if c.Jail.BadRequestPeriod, err = parseDuration(cfg.Jail.BadRequestPeriod, defaultJailBadRequestPeriod); err != nil {
		return config{}, fmt.Errorf("invalid jail bad request period: %q: %w", cfg.Jail.BadRequestPeriod, err)
	}
	if c.Jail.Duration, err = parseDuration(cfg.Jail.Duration, defaultJailDuration); err != nil {
		return config{}, fmt.Errorf("invalid jail duration: %q: %w", cfg.Jail.Duration, err)
	}
	return c, nil
}

// parseDuration parses a duration.
func parseDuration(s string, def time.Duration) (time.Duration, error) {
	if s != "" {
		return time.ParseDuration(s)
	}
	return def, nil
}

// mapsCopy is a quick implementation of copying all key/value pairs from
// headers, as traefik's yaegi doesn't support generics.
func mapsCopy(dst, src http.Header) {
	for k, z := range src {
		v := make([]string, len(src[k]))
		copy(v, z)
		dst[k] = v
	}
}
