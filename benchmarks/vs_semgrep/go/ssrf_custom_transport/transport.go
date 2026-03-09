package main

import (
	"log"
	"net/http"
	"time"
)

type LoggingTransport struct {
	inner http.RoundTripper
}

func (t *LoggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	start := time.Now()
	resp, err := t.inner.RoundTrip(req)
	log.Printf("%s %s %v", req.Method, req.URL, time.Since(start))
	return resp, err
}

func NewHTTPClient() *http.Client {
	return &http.Client{
		Timeout: 10 * time.Second,
		Transport: &LoggingTransport{
			inner: http.DefaultTransport,
		},
	}
}
