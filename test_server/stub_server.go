package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
)

func main() {
	port := flag.Int("port", 3000, "Port to run the stub server on")
	flag.Parse()

	mux := http.NewServeMux()

	// Simulate root handler
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		log.Printf("Received request on /: %s %s", r.Method, r.URL.Path)
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "Hello from root path!\n")
	})

	addr := fmt.Sprintf(":%d", *port)
	log.Printf("Stub server running on http://localhost%s", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}
