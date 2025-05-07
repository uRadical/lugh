package main

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/corazawaf/coraza/v3"
)

// Test payloads
var (
	smallPayload  = []byte(`{"status":"ok","message":"small payload"}`)
	mediumPayload = make([]byte, 10*1024)  // 10KB
	largePayload  = make([]byte, 100*1024) // 100KB
)

func init() {
	// Initialize payloads with patterns
	for i := range mediumPayload {
		mediumPayload[i] = byte(i % 256)
	}
	for i := range largePayload {
		largePayload[i] = byte(i % 256)
	}
}

// setupBackend creates a test backend server
func setupBackend(payload []byte) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write(payload)
	}))
}

// setupProxy creates a Lugh proxy with or without WAF
func setupProxy(backend *httptest.Server, enableWAF bool) *httptest.Server {
	// Create proxy config
	config := Config{
		Server: struct {
			Listen string `yaml:"listen"`
		}{
			Listen: "localhost:0",
		},
		Locations: []struct {
			Path      string `yaml:"path"`
			ProxyPass string `yaml:"proxy_pass"`
			RateLimit struct {
				RequestsPerSecond int `yaml:"requests_per_second"`
				Burst             int `yaml:"burst"`
			} `yaml:"rate_limit"`
		}{
			{
				Path:      "/api",
				ProxyPass: backend.URL,
				RateLimit: struct {
					RequestsPerSecond int `yaml:"requests_per_second"`
					Burst             int `yaml:"burst"`
				}{
					RequestsPerSecond: 1000, // High limit to avoid affecting benchmarks
					Burst:             1000,
				},
			},
		},
		WAF: struct {
			Enabled         bool   `yaml:"enabled"`
			CustomRulesPath string `yaml:"custom_rules_path"`
		}{
			Enabled:         enableWAF,
			CustomRulesPath: "",
		},
	}

	// Initialize rate limiters
	rateLimiters = make(map[string]*RateLimiter)
	for _, location := range config.Locations {
		rateLimiters[location.Path] = NewRateLimiter(
			location.RateLimit.RequestsPerSecond,
			location.RateLimit.Burst,
		)
	}

	// Initialize WAF if enabled
	var waf coraza.WAF
	if enableWAF {
		var err error
		// Use minimal WAF config for benchmarking
		waf, err = coraza.NewWAF(coraza.NewWAFConfig().
			WithDirectives(`
				SecRuleEngine On
				SecRule REQUEST_URI "@rx .*" "id:1000,phase:1,pass"
			`))
		if err != nil {
			panic(err) // For benchmark setup only
		}
	}

	// Create and return proxy server
	proxyHandler := createProxyHandler(config, waf)
	return httptest.NewServer(proxyHandler)
}

// benchmarkRequest performs a single request and returns the response
func benchmarkRequest(b *testing.B, url string) {
	resp, err := http.Get(url)
	if err != nil {
		b.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	// Read and discard response body
	io.Copy(io.Discard, resp.Body)
}

// BenchmarkSmallNoWAF benchmarks small payload without WAF
func BenchmarkSmallNoWAF(b *testing.B) {
	backend := setupBackend(smallPayload)
	defer backend.Close()

	proxy := setupProxy(backend, false)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}

// BenchmarkSmallWithWAF benchmarks small payload with WAF
func BenchmarkSmallWithWAF(b *testing.B) {
	backend := setupBackend(smallPayload)
	defer backend.Close()

	proxy := setupProxy(backend, true)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}

// BenchmarkMediumNoWAF benchmarks medium payload without WAF
func BenchmarkMediumNoWAF(b *testing.B) {
	backend := setupBackend(mediumPayload)
	defer backend.Close()

	proxy := setupProxy(backend, false)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}

// BenchmarkMediumWithWAF benchmarks medium payload with WAF
func BenchmarkMediumWithWAF(b *testing.B) {
	backend := setupBackend(mediumPayload)
	defer backend.Close()

	proxy := setupProxy(backend, true)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}

// BenchmarkLargeNoWAF benchmarks large payload without WAF
func BenchmarkLargeNoWAF(b *testing.B) {
	backend := setupBackend(largePayload)
	defer backend.Close()

	proxy := setupProxy(backend, false)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}

// BenchmarkLargeWithWAF benchmarks large payload with WAF
func BenchmarkLargeWithWAF(b *testing.B) {
	backend := setupBackend(largePayload)
	defer backend.Close()

	proxy := setupProxy(backend, true)
	defer proxy.Close()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		benchmarkRequest(b, proxy.URL+"/api")
	}
}
