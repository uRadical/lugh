package main

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	_ "net/http/pprof"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	coreset "github.com/corazawaf/coraza-coreruleset/v4"
	"github.com/corazawaf/coraza/v3"
	"github.com/corazawaf/coraza/v3/debuglog"
	"github.com/fsnotify/fsnotify"
	"gopkg.in/yaml.v3"
)

// Config represents the server configuration
type Config struct {
	Server struct {
		Listen string `yaml:"listen"`
	} `yaml:"server"`

	Locations []struct {
		Path      string `yaml:"path"`
		ProxyPass string `yaml:"proxy_pass"`
		RateLimit struct {
			RequestsPerSecond int `yaml:"requests_per_second"`
			Burst             int `yaml:"burst"`
		} `yaml:"rate_limit"`
	} `yaml:"locations"`

	WAF struct {
		Enabled         bool   `yaml:"enabled"`
		CustomRulesPath string `yaml:"custom_rules_path"`
	} `yaml:"waf"`
}

// RateLimiter implements a simple token bucket rate limiter
type RateLimiter struct {
	tokens         int
	capacity       int
	refillRate     int
	lastRefillTime time.Time
	mu             chan struct{} // Simple mutex using a channel
}

// NewRateLimiter creates a new rate limiter with the given capacity and refill rate
func NewRateLimiter(requestsPerSecond, burst int) *RateLimiter {
	return &RateLimiter{
		tokens:         burst,
		capacity:       burst,
		refillRate:     requestsPerSecond,
		lastRefillTime: time.Now(),
		mu:             make(chan struct{}, 1),
	}
}

// Allow checks if a request should be allowed based on the rate limit
func (l *RateLimiter) Allow() bool {
	l.mu <- struct{}{}        // Acquire lock
	defer func() { <-l.mu }() // Release lock

	now := time.Now()
	elapsed := now.Sub(l.lastRefillTime)
	l.lastRefillTime = now

	// Refill tokens based on elapsed time
	newTokens := int(float64(l.refillRate) * elapsed.Seconds())
	if newTokens > 0 {
		l.tokens = min(l.capacity, l.tokens+newTokens)
	}

	if l.tokens > 0 {
		l.tokens--
		return true
	}

	return false
}

// Global map of path prefixes to rate limiters
var rateLimiters = make(map[string]*RateLimiter)

func main() {
	// Parse command line arguments
	configPath := flag.String("config", "/etc/lugh/config.yaml", "Path to configuration file")
	flag.Parse()

	// Load configuration
	config, err := loadConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load configuration: %v", err)
	}

	// Set up rate limiters for each location
	for _, location := range config.Locations {
		rateLimiters[location.Path] = NewRateLimiter(
			location.RateLimit.RequestsPerSecond,
			location.RateLimit.Burst,
		)
	}

	// Initialize WAF if enabled
	var waf coraza.WAF
	if config.WAF.Enabled {
		waf, err = initializeWAF(config.WAF.CustomRulesPath)
		if err != nil {
			log.Fatalf("Failed to initialize WAF: %v", err)
		}

		// Watch custom rules directory for changes if specified
		if config.WAF.CustomRulesPath != "" {
			go watchRulesDirectory(config.WAF.CustomRulesPath, &waf)
		}
	}

	go func() {
		log.Println("Starting pprof on :6060")
		if err := http.ListenAndServe("localhost:6060", nil); err != nil {
			log.Printf("pprof server error: %v", err)
		}
	}()

	// Create a new HTTP server
	server := &http.Server{
		Addr:    config.Server.Listen,
		Handler: createProxyHandler(config, waf),
	}

	// Start the server
	log.Printf("Lugh proxy server starting on %s", config.Server.Listen)
	log.Fatal(server.ListenAndServe())
}

// loadConfig loads the configuration from the specified file
func loadConfig(path string) (Config, error) {
	var config Config

	data, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("error reading config file: %w", err)
	}

	err = yaml.Unmarshal(data, &config)
	if err != nil {
		return config, fmt.Errorf("error parsing config file: %w", err)
	}

	return config, nil
}

// initializeWAF sets up the Coraza WAF with core rule set and custom rules
func initializeWAF(customRulesPath string) (coraza.WAF, error) {
	// Create a WAF configuration
	wafConfig := coraza.NewWAFConfig()

	// Set up logger
	logger := debuglog.Default()
	wafConfig = wafConfig.WithDebugLogger(logger)

	// Enable request and response body processing
	wafConfig = wafConfig.WithRequestBodyAccess().WithResponseBodyAccess()

	// Set appropriate limits for body processing
	wafConfig = wafConfig.WithRequestBodyLimit(10 * 1024 * 1024)  // 10MB
	wafConfig = wafConfig.WithResponseBodyLimit(10 * 1024 * 1024) // 10MB

	// Set MIME types for response body processing
	wafConfig = wafConfig.WithResponseBodyMimeTypes([]string{
		"text/html",
		"text/xml",
		"text/plain",
		"application/json",
		"application/xml",
		"application/javascript",
		"application/xhtml+xml",
	})

	// Set up directives from core rule set
	directives := `
	# Include Coraza recommended configuration
	Include @coraza.conf-recommended
	
	# Include CRS setup configuration
	Include @crs-setup.conf.example
	
	# Include OWASP CRS rules
	Include @owasp_crs/*.conf
	`

	// Use CRS filesystem
	wafConfig = wafConfig.WithDirectives(directives).WithRootFS(coreset.FS)

	// Load custom rules if path is provided
	if customRulesPath != "" {
		// Prepare include directives for custom rules
		var customDirectives strings.Builder
		files, err := filepath.Glob(filepath.Join(customRulesPath, "*.conf"))
		if err == nil && len(files) > 0 {
			for _, file := range files {
				customDirectives.WriteString(fmt.Sprintf("Include %s\n", file))
			}

			// Append custom directives to the configuration
			wafConfig = wafConfig.WithDirectives(customDirectives.String())
		}
	}

	// Initialize WAF
	waf, err := coraza.NewWAF(wafConfig)
	if err != nil {
		return nil, fmt.Errorf("error initializing WAF: %w", err)
	}

	return waf, nil
}

// watchRulesDirectory monitors the custom rules directory for changes and reloads rules
func watchRulesDirectory(rulesPath string, waf *coraza.WAF) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		log.Printf("Error setting up file watcher: %v", err)
		return
	}
	defer watcher.Close()

	err = watcher.Add(rulesPath)
	if err != nil {
		log.Printf("Error watching rules directory: %v", err)
		return
	}

	log.Printf("Watching for changes in custom rules directory: %s", rulesPath)

	for {
		select {
		case event, ok := <-watcher.Events:
			if !ok {
				return
			}
			if event.Op&(fsnotify.Write|fsnotify.Create) != 0 && filepath.Ext(event.Name) == ".conf" {
				log.Printf("Detected changes in %s, reloading rules", event.Name)

				// Reload WAF with updated rules
				newWAF, err := initializeWAF(rulesPath)
				if err != nil {
					log.Printf("Failed to reload WAF rules: %v", err)
					continue
				}

				// Atomically replace WAF
				*waf = newWAF
				log.Printf("WAF rules reloaded successfully")
			}
		case err, ok := <-watcher.Errors:
			if !ok {
				return
			}
			log.Printf("Watcher error: %v", err)
		}
	}
}

// createProxyHandler creates the HTTP handler for the proxy
func createProxyHandler(config Config, waf coraza.WAF) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Debug log
		log.Printf("Handling request for path: %s", r.URL.Path)

		// Find the matching location for the request path
		var targetLocation *struct {
			Path      string `yaml:"path"`
			ProxyPass string `yaml:"proxy_pass"`
			RateLimit struct {
				RequestsPerSecond int `yaml:"requests_per_second"`
				Burst             int `yaml:"burst"`
			} `yaml:"rate_limit"`
		}

		// First try exact match
		for i, location := range config.Locations {
			if r.URL.Path == location.Path {
				targetLocation = &config.Locations[i]
				log.Printf("Found exact path match: %s", location.Path)
				break
			}
		}

		// If no exact match, try prefix match
		if targetLocation == nil {
			for i, location := range config.Locations {
				if location.Path != "/" &&
					len(r.URL.Path) >= len(location.Path) &&
					r.URL.Path[:len(location.Path)] == location.Path {
					targetLocation = &config.Locations[i]
					log.Printf("Found prefix path match: %s", location.Path)
					break
				}
			}
		}

		// Check if this is a Vite asset request based on Referer header or path patterns
		if targetLocation == nil || targetLocation.Path == "/" {
			// Check if it's a Vite-specific path
			isViteAsset := strings.HasPrefix(r.URL.Path, "/@") ||
				strings.HasPrefix(r.URL.Path, "/src/") ||
				strings.HasPrefix(r.URL.Path, "/node_modules/") ||
				r.URL.Path == "/vite.svg" ||
				strings.Contains(r.URL.Path, ".js") ||
				strings.Contains(r.URL.Path, ".css")

			// Check referer header
			referer := r.Header.Get("Referer")
			if isViteAsset && referer != "" {
				refURL, err := url.Parse(referer)
				if err == nil && strings.HasPrefix(refURL.Path, "/app") {
					// This is an asset request from /app, route it to the app location
					for i, location := range config.Locations {
						if location.Path == "/app" {
							targetLocation = &config.Locations[i]
							log.Printf("Routing Vite asset %s to /app based on referer", r.URL.Path)
							break
						}
					}
				}
			}
		}

		// If still no match, use root location if available
		if targetLocation == nil {
			for i, location := range config.Locations {
				if location.Path == "/" {
					targetLocation = &config.Locations[i]
					log.Printf("Using root path as fallback")
					break
				}
			}
		}

		// If no matching location found
		if targetLocation == nil {
			if len(config.Locations) > 0 {
				targetLocation = &config.Locations[0]
				log.Printf("No match found, using first location: %s", targetLocation.Path)
			} else {
				log.Printf("No locations configured")
				http.Error(w, "No proxy configuration available", http.StatusInternalServerError)
				return
			}
		}

		// Apply rate limiting
		if limiter, ok := rateLimiters[targetLocation.Path]; ok {
			if !limiter.Allow() {
				http.Error(w, "Rate limit exceeded", http.StatusTooManyRequests)
				return
			}
		}

		// Apply WAF if enabled
		if config.WAF.Enabled && waf != nil {
			tx := waf.NewTransaction()
			defer func() {
				if tx != nil {
					tx.ProcessLogging()
				}
			}()

			// Process connection
			clientIP, clientPort, err := net.SplitHostPort(r.RemoteAddr)
			if err != nil {
				clientIP = r.RemoteAddr
				clientPort = "0"
			}

			serverIP, serverPort, err := net.SplitHostPort(r.Host)
			if err != nil {
				serverIP = r.Host
				serverPort = "80"
				if r.TLS != nil {
					serverPort = "443"
				}
			}

			cPort, _ := strconv.Atoi(clientPort)
			sPort, _ := strconv.Atoi(serverPort)

			tx.ProcessConnection(clientIP, cPort, serverIP, sPort)

			// Process URI and request headers
			tx.ProcessURI(r.URL.String(), r.Method, r.Proto)

			// Process request headers
			for name, values := range r.Header {
				for _, value := range values {
					tx.AddRequestHeader(name, value)
				}
			}

			// Process request headers
			tx.ProcessRequestHeaders()

			// Process request body if present
			if r.Body != nil && r.ContentLength > 0 {
				// We need to read the body without consuming it
				bodyBytes, err := io.ReadAll(r.Body)
				if err == nil {
					// Restore the body for the proxy
					r.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))

					// Process the request body with WAF - first write the body
					_, _, err := tx.WriteRequestBody(bodyBytes)
					if err != nil {
						log.Printf("Error writing request body: %v", err)
					}

					// Then process it
					interruption, err := tx.ProcessRequestBody()
					if err != nil {
						log.Printf("Error processing request body: %v", err)
					}

					// Check for body interruption
					if interruption != nil {
						log.Printf("WAF blocked request during body processing: %d", interruption.Status)
						http.Error(w, "Request blocked by WAF", interruption.Status)
						return
					}
				} else {
					log.Printf("Error reading request body: %v", err)
				}
			}

			// Check for interruption
			interruption := tx.Interruption()
			if interruption != nil {
				log.Printf("WAF blocked request: %d", interruption.Status)
				http.Error(w, "Request blocked by WAF", int(interruption.Status))
				return
			}
		}

		// Set up target URL for proxy
		targetURL, err := url.Parse(targetLocation.ProxyPass)
		if err != nil {
			log.Printf("Invalid proxy target: %s - %v", targetLocation.ProxyPass, err)
			http.Error(w, "Invalid proxy target", http.StatusInternalServerError)
			return
		}

		// Create reverse proxy
		proxy := httputil.NewSingleHostReverseProxy(targetURL)

		// Log the proxy target
		log.Printf("Proxying to: %s (location path: %s)", targetURL.String(), targetLocation.Path)

		// Set up custom director to modify the request before sending
		originalDirector := proxy.Director
		proxy.Director = func(req *http.Request) {
			// Log original path
			originalPath := req.URL.Path

			originalDirector(req)

			// Strip the location prefix from the path if it's not root
			if targetLocation.Path != "/" && strings.HasPrefix(req.URL.Path, targetLocation.Path) {
				req.URL.Path = strings.TrimPrefix(req.URL.Path, targetLocation.Path)
				if req.URL.Path == "" {
					req.URL.Path = "/"
				}
				log.Printf("Path rewrite: %s -> %s", originalPath, req.URL.Path)
			}

			// Log final request URL
			log.Printf("Final request URL: %s", req.URL.String())

			// Set the Host header to match the backend
			req.Host = targetURL.Host
			req.Header.Set("Host", targetURL.Host)
			log.Printf("Setting Host header to: %s (was: %s)", targetURL.Host, r.Host)

			// Set additional headers like nginx does
			req.Header.Set("X-Real-IP", r.RemoteAddr)
			req.Header.Set("X-Forwarded-Proto", r.URL.Scheme)
			req.Header.Set("X-Forwarded-Host", r.Host)

			// Forward the Origin header
			if origin := r.Header.Get("Origin"); origin != "" {
				req.Header.Set("Origin", origin)
			}

			// Forward cookies
			if cookies := r.Header.Get("Cookie"); cookies != "" {
				req.Header.Set("Cookie", cookies)
			}
		}

		// Serve the request through the proxy
		proxy.ServeHTTP(w, r)
	})
}
