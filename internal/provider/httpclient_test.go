package provider

import (
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNewHTTPClientRejectsPlainHTTP(t *testing.T) {
	_, err := newHTTPClient("http://gw.example.com", "", false, time.Second)
	if err == nil || !strings.Contains(err.Error(), "clear text") {
		t.Fatalf("got %v", err)
	}
	if _, err := newHTTPClient("http://localhost:8080", "", true, time.Second); err != nil {
		t.Fatalf("insecure_http should allow http: %v", err)
	}
}

func TestNewHTTPClientRejectsBadURLs(t *testing.T) {
	for _, u := range []string{"gw.example.com", "ftp://gw.example.com", "https://user:pass@gw.example.com"} {
		if _, err := newHTTPClient(u, "", true, time.Second); err == nil {
			t.Errorf("%s: want error", u)
		}
	}
}

func TestNewHTTPClientRejectsBadCA(t *testing.T) {
	if _, err := newHTTPClient("https://gw.example.com", "not a cert", false, time.Second); err == nil {
		t.Fatal("want error")
	}
}

func TestNewHTTPClientDoesNotFollowRedirects(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("redirect was followed; X-API-Key=%q", r.Header.Get("X-API-Key"))
	}))
	defer target.Close()
	gw := httptest.NewServer(http.RedirectHandler(target.URL, http.StatusFound))
	defer gw.Close()

	c, err := newHTTPClient(gw.URL, "", true, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL, http.NoBody)
	req.Header.Set("X-API-Key", "secret")
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestNewHTTPClientTrustsOnlyGivenCA(t *testing.T) {
	gw := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	defer gw.Close()

	c, err := newHTTPClient(gw.URL, "", false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	req, _ := http.NewRequestWithContext(t.Context(), http.MethodGet, gw.URL, http.NoBody)
	if resp, err := c.Do(req); err == nil {
		resp.Body.Close()
		t.Fatal("self-signed certificate was trusted without ca_cert_pem")
	}

	caPEM := certPEM(gw.Certificate().Raw)
	c, err = newHTTPClient(gw.URL, caPEM, false, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Do(req)
	if err != nil {
		t.Fatalf("pinned CA not trusted: %v", err)
	}
	resp.Body.Close()
}

func certPEM(der []byte) string {
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}
