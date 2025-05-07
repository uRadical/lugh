package main

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/corazawaf/coraza/v3"
	"gopkg.in/yaml.v3"
)

// TestLoadConfig verifies that configuration is loaded correctly
func TestLoadConfig(t *testing.T) {
	// Create a temporary config file
	tmpDir := t.TempDir()
	configPath := filepath.Join(tmpDir, "config.yaml")
	
	configContent := `
server:
  listen: "0.0.0.0:8080"

locations:
  - path: "/api"
    proxy_pass: "http://backend:3000"
    rate_limit:
      requests_per_second: 10
      burst: 20
  
  - path: "/"
    proxy_pass: "http://frontend:8080"
    rate_limit:
      requests_per_second: 30
      burst: 50

waf:
  enabled: true
  custom_rules_path: "/etc/lugh/rules"
`
	
	err := os.WriteFile(configPath, []byte(configContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test config file: %v", err)
	}
	
	// Load the configuration
	config, err := loadConfig(configPath)
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}
	
	// Verify the loaded configuration
	if config.Server.Listen != "0.0.0.0:8080" {
		t.Errorf("Expected listen address '0.0.0.0:8080', got '%s'", config.Server.Listen)
	}
	
	if len(config.Locations) != 2 {
		t.Fatalf("Expected 2 locations, got %d", len(config.Locations))
	}
	
	if config.Locations[0].Path != "/api" || config.Locations[0].ProxyPass != "http://backend:3000" {
		t.Errorf("API location not configured correctly")
	}
	
	if config.Locations[0].RateLimit.RequestsPerSecond != 10 || config.Locations[0].RateLimit.Burst != 20 {
		t.Errorf("API rate limit not configured correctly")
	}
	
	if !config.WAF.Enabled || config.WAF.CustomRulesPath != "/etc/lugh/rules" {
		t.Errorf("WAF configuration not loaded correctly")
	}
}

// TestRateLimiter verifies that the rate limiter works correctly
func TestRateLimiter(t *testing.T) {
	// Create a rate limiter with 5 requests per second and a burst of 10
	limiter := NewRateLimiter(5, 10)
	
	// Initially, should allow burst number of requests
	for i := 0; i < 10; i++ {
		if !limiter.Allow() {
			t.Errorf("Expected request %d to be allowed", i+1)
		}
	}
	
	// Next request should be denied (burst is used up)
	if limiter.Allow() {
		t.Errorf("Expected request to be denied after burst")
	}
	
	// Wait for tokens to refill (1 second should give us 5 more tokens)
	time.Sleep(1 * time.Second)
	
	// Should now allow 5 more requests
	for i := 0; i < 5; i++ {
		if !limiter.Allow() {
			t.Errorf("Expected request %d to be allowed after refill", i+1)
		}
	}
	
	// Next request should be denied again
	if limiter.Allow() {
		t.Errorf("Expected request to be denied after refill")
	}
}

// mockWAF creates a simple WAF that blocks specific attack patterns
func mockWAF(t *testing.T) coraza.WAF {
	// Create temporary directory for test rules
	tmpDir := t.TempDir()
	rulesPath := filepath.Join(tmpDir, "rules")
	err := os.MkdirAll(rulesPath, 0755)
	if err != nil {
		t.Fatalf("Failed to create test rules directory: %v", err)
	}
	
	// Create a simple rule to block XSS attacks
	ruleFile := filepath.Join(rulesPath, "xss.conf")
	ruleContent := `
# Enable the rule engine
SecRuleEngine On

# Basic XSS detection rule
SecRule ARGS:q "@contains <script>" "id:1000,phase:1,deny,status:403,log,msg:'XSS Attack Detected'"
SecRule ARGS:q "@contains alert(" "id:1001,phase:1,deny,status:403,log,msg:'XSS Attack Detected'"
SecRule ARGS:q "@contains UNION SELECT" "id:1002,phase:1,deny,status:403,log,msg:'SQL Injection Attack Detected'"
`
	err = os.WriteFile(ruleFile, []byte(ruleContent), 0644)
	if err != nil {
		t.Fatalf("Failed to create test rule file: %v", err)
	}
	
	// Create WAF configuration
	wafConfig := coraza.NewWAFConfig()
	
	// Add directives for test rules
	wafConfig = wafConfig.WithDirectives(fmt.Sprintf("Include %s", ruleFile))
	
	// Enable request and response body processing
	wafConfig = wafConfig.WithRequestBodyAccess().WithResponseBodyAccess()
	
	// Initialize WAF with test configuration
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		t.Fatalf("Failed to initialize test WAF: %v", err)
	}
	
	return waf
}

// mockConfig creates a test configuration
func mockConfig() Config {
	var config Config
	configYaml := `
server:
  listen: "127.0.0.1:8080"

locations:
  - path: "/api"
    proxy_pass: "http://backend:3000"
    rate_limit:
      requests_per_second: 10
      burst: 20
  
  - path: "/"
    proxy_pass: "http://frontend:8080"
    rate_limit:
      requests_per_second: 30
      burst: 50

waf:
  enabled: true
  custom_rules_path: "/etc/lugh/rules"
`
	err := yaml.Unmarshal([]byte(configYaml), &config)
	if err != nil {
		panic(err)
	}
	
	return config
}

// setupTestServer creates a test server with the proxy handler
func setupTestServer(t *testing.T, waf coraza.WAF) (*httptest.Server, *httptest.Server, *httptest.Server) {
	// Create mock backend servers
	apiServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","service":"api"}`))
	}))
	
	frontendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><h1>Frontend</h1></body></html>`))
	}))
	
	// Create test configuration with actual server addresses
	config := mockConfig()
	config.Locations[0].Path = "/api" // Ensure path is set correctly
	config.Locations[0].ProxyPass = apiServer.URL
	config.Locations[1].Path = "/" // Ensure path is set correctly
	config.Locations[1].ProxyPass = frontendServer.URL
	
	// Set up rate limiters
	rateLimiters = make(map[string]*RateLimiter)
	for _, location := range config.Locations {
		rateLimiters[location.Path] = NewRateLimiter(
			location.RateLimit.RequestsPerSecond,
			location.RateLimit.Burst,
		)
	}
	
	// Create the proxy server
	proxyHandler := createProxyHandler(config, waf)
	proxyServer := httptest.NewServer(proxyHandler)
	
	return proxyServer, apiServer, frontendServer
}

// TestRouting verifies that requests are routed to the correct backend
func TestRouting(t *testing.T) {
	proxyServer, apiServer, frontendServer := setupTestServer(t, nil)
	defer proxyServer.Close()
	defer apiServer.Close()
	defer frontendServer.Close()
	
	// Test API route
	resp, err := http.Get(proxyServer.URL + "/api")
	if err != nil {
		t.Fatalf("Failed to make API request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read API response: %v", err)
	}
	
	if !bytes.Contains(body, []byte(`"service":"api"`)) {
		t.Errorf("Expected API response, got: %s", body)
	}
	
	// Test frontend route
	resp, err = http.Get(proxyServer.URL + "/")
	if err != nil {
		t.Fatalf("Failed to make frontend request: %v", err)
	}
	defer resp.Body.Close()
	
	body, err = io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read frontend response: %v", err)
	}
	
	if !bytes.Contains(body, []byte(`<h1>Frontend</h1>`)) {
		t.Errorf("Expected frontend response, got: %s", body)
	}
}

// TestWAF verifies that the WAF blocks malicious requests
func TestWAF(t *testing.T) {
	waf := mockWAF(t)
	proxyServer, apiServer, frontendServer := setupTestServer(t, waf)
	defer proxyServer.Close()
	defer apiServer.Close()
	defer frontendServer.Close()
	
	// Test XSS attack (should be blocked)
	resp, err := http.Get(proxyServer.URL + "/api?q=<script>alert(1)</script>")
	if err != nil {
		t.Fatalf("Failed to make XSS request: %v", err)
	}
	defer resp.Body.Close()
	
	// WAF should block this request with a 403
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for XSS attack, got: %d", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response body: %s", body)
	}
	
	// Test SQL injection attack (should be blocked)
	resp, err = http.Get(proxyServer.URL + "/api?q=1%20UNION%20SELECT%20username,password%20FROM%20users")
	if err != nil {
		t.Fatalf("Failed to make SQL injection request: %v", err)
	}
	defer resp.Body.Close()
	
	// WAF should block this request with a 403
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("Expected 403 for SQL injection attack, got: %d", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response body: %s", body)
	}
	
	// Test legitimate request (should be allowed)
	resp, err = http.Get(proxyServer.URL + "/api?q=legitimate")
	if err != nil {
		t.Fatalf("Failed to make legitimate request: %v", err)
	}
	defer resp.Body.Close()
	
	// WAF should allow this request
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 for legitimate request, got: %d", resp.StatusCode)
		body, _ := io.ReadAll(resp.Body)
		t.Logf("Response body: %s", body)
	}
}

// TestRateLimiting verifies that rate limiting works
func TestRateLimiting(t *testing.T) {
	proxyServer, apiServer, frontendServer := setupTestServer(t, nil)
	defer proxyServer.Close()
	defer apiServer.Close()
	defer frontendServer.Close()
	
	// Configure a very strict rate limiter for testing
	rateLimiters["/api"] = NewRateLimiter(1, 2) // 1 req/s, burst of 2
	
	// First two requests should succeed (burst capacity)
	for i := 0; i < 2; i++ {
		resp, err := http.Get(proxyServer.URL + "/api")
		if err != nil {
			t.Fatalf("Failed to make request %d: %v", i+1, err)
		}
		defer resp.Body.Close()
		
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected request %d to succeed with 200, got: %d", i+1, resp.StatusCode)
		}
	}
	
	// Third request should be rate limited
	resp, err := http.Get(proxyServer.URL + "/api")
	if err != nil {
		t.Fatalf("Failed to make rate-limited request: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("Expected 429 for rate-limited request, got: %d", resp.StatusCode)
	}
	
	// Wait for token to refill (should take 1 second for 1 token)
	time.Sleep(1100 * time.Millisecond)
	
	// Next request should succeed again
	resp, err = http.Get(proxyServer.URL + "/api")
	if err != nil {
		t.Fatalf("Failed to make request after wait: %v", err)
	}
	defer resp.Body.Close()
	
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected 200 after rate limit refill, got: %d", resp.StatusCode)
	}
}

// TestHeaderForwarding verifies that headers are forwarded correctly
func TestHeaderForwarding(t *testing.T) {
	// Create a test backend server that echoes back the received headers
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		
		// Echo the headers we care about
		receivedHeaders := map[string]string{
			"Host":              r.Host,
			"X-Real-IP":         r.Header.Get("X-Real-IP"),
			"X-Forwarded-For":   r.Header.Get("X-Forwarded-For"),
			"X-Forwarded-Proto": r.Header.Get("X-Forwarded-Proto"),
			"Origin":            r.Header.Get("Origin"),
			"Cookie":            r.Header.Get("Cookie"),
		}
		
		// Return headers as JSON
		w.Write([]byte(`{"headers":` + mapToJSON(receivedHeaders) + `}`))
	}))
	defer backendServer.Close()
	
	// Create test configuration with the echo server
	config := mockConfig()
	config.Locations[0].ProxyPass = backendServer.URL
	
	// Set up rate limiters
	rateLimiters = make(map[string]*RateLimiter)
	for _, location := range config.Locations {
		rateLimiters[location.Path] = NewRateLimiter(
			location.RateLimit.RequestsPerSecond,
			location.RateLimit.Burst,
		)
	}
	
	// Create the proxy server
	proxyHandler := createProxyHandler(config, nil)
	proxyServer := httptest.NewServer(proxyHandler)
	defer proxyServer.Close()
	
	// Create a client that preserves cookies
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	
	// Create request with custom headers
	req, err := http.NewRequest("GET", proxyServer.URL+"/api", nil)
	if err != nil {
		t.Fatalf("Failed to create request: %v", err)
	}
	
	req.Header.Set("Origin", "http://example.com")
	req.Header.Set("Cookie", "session=abc123; user=john")
	
	// Send the request
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("Failed to send request: %v", err)
	}
	defer resp.Body.Close()
	
	// Read the response
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response: %v", err)
	}
	
	// Verify headers were properly forwarded
	if !bytes.Contains(body, []byte(`"Origin":"http://example.com"`)) {
		t.Errorf("Origin header not forwarded correctly: %s", body)
	}
	
	if !bytes.Contains(body, []byte(`"Cookie":"session=abc123; user=john"`)) {
		t.Errorf("Cookie header not forwarded correctly: %s", body)
	}
	
	if !bytes.Contains(body, []byte(`"X-Real-IP"`)) {
		t.Errorf("X-Real-IP header not set correctly: %s", body)
	}
	
	if !bytes.Contains(body, []byte(`"X-Forwarded-Proto"`)) {
		t.Errorf("X-Forwarded-Proto header not set correctly: %s", body)
	}
}

// Helper function to convert a map to a JSON string
func mapToJSON(m map[string]string) string {
	var buf bytes.Buffer
	buf.WriteString("{")
	first := true
	for k, v := range m {
		if !first {
			buf.WriteString(",")
		}
		first = false
		buf.WriteString(`"` + k + `":"` + v + `"`)
	}
	buf.WriteString("}")
	return buf.String()
}