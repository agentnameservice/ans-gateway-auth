// Command echo is a development upstream that returns the request it received
// as JSON, so the identity headers the gateway injects can be inspected.
package main

import (
	"encoding/json"
	"flag"
	"io"
	"log"
	"net/http"
	"time"
)

const (
	maxBodyBytes      = 4 << 20
	readHeaderTimeout = 5 * time.Second
)

type echoResponse struct {
	Method  string              `json:"method"`
	Path    string              `json:"path"`
	Headers map[string][]string `json:"headers"`
	Body    string              `json:"body"`
}

func main() {
	listen := flag.String("listen", "127.0.0.1:8081", "address to listen on")
	flag.Parse()

	srv := &http.Server{
		Addr:              *listen,
		Handler:           http.HandlerFunc(echo),
		ReadHeaderTimeout: readHeaderTimeout,
	}
	log.Printf("echo upstream listening on %s", *listen)
	log.Fatal(srv.ListenAndServe())
}

func echo(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodyBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(echoResponse{
		Method:  r.Method,
		Path:    r.URL.RequestURI(),
		Headers: r.Header,
		Body:    string(body),
	})
}
