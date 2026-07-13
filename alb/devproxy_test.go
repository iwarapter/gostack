package alb

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestNewDevProxy(t *testing.T) {
	var gotHost, gotPath string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotHost, gotPath = r.Host, r.URL.Path
		fmt.Fprint(w, "hello")
	}))
	defer backend.Close()

	h, err := newDevProxy(backend.URL)
	if err != nil {
		t.Fatalf("newDevProxy: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://alb.127.0.0.1.nip.io:8080/assets/app.js", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("status = %d, want 200", rec.Code)
	}
	if body := rec.Body.String(); body != "hello" {
		t.Errorf("body = %q, want %q", body, "hello")
	}
	wantHost := strings.TrimPrefix(backend.URL, "http://")
	if gotHost != wantHost {
		t.Errorf("backend Host = %q, want %q", gotHost, wantHost)
	}
	if gotPath != "/assets/app.js" {
		t.Errorf("backend path = %q, want %q", gotPath, "/assets/app.js")
	}
}

func TestNewDevProxyInvalidURL(t *testing.T) {
	if _, err := newDevProxy("://not-a-url"); err == nil {
		t.Error("expected error for invalid dev-proxy url, got nil")
	}
}
