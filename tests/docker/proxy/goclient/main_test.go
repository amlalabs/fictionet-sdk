package main

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

func TestTruncatedBodyIsAnError(t *testing.T) {
	const greeting = "hello from https example.test 443 over HTTP/2.0\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(greeting)+1))
		if _, err := io.WriteString(w, greeting); err != nil {
			t.Error(err)
			return
		}
		controller := http.NewResponseController(w)
		if err := controller.Flush(); err != nil {
			t.Error(err)
			return
		}
		conn, _, err := controller.Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		if err := conn.Close(); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	_, _, err := fetch(server.URL)
	if err == nil {
		t.Fatal("fetch succeeded with a truncated body")
	}
	if !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("fetch error = %v, want unexpected EOF", err)
	}
	if !strings.Contains(err.Error(), server.URL) {
		t.Fatalf("fetch error %q does not name URL %q", err, server.URL)
	}
}

func TestCompleteBody(t *testing.T) {
	const greeting = "hello from https example.test 443 over HTTP/2.0\n"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Length", strconv.Itoa(len(greeting)))
		if _, err := io.WriteString(w, greeting); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()

	status, body, err := fetch(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	if status != http.StatusOK {
		t.Errorf("status = %d, want %d", status, http.StatusOK)
	}
	if string(body) != greeting {
		t.Errorf("body = %q, want %q", body, greeting)
	}
}
