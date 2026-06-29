package vt

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestLookupParsesStats(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":` +
			`{"malicious":48,"suspicious":2,"harmless":10,"undetected":12,"timeout":0}}}}`))
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	c := NewClient("key")
	found, mal, total, err := c.Lookup("abc")
	if err != nil || !found {
		t.Fatalf("found=%v err=%v", found, err)
	}
	if mal != 50 || total != 72 {
		t.Fatalf("mal=%d total=%d", mal, total)
	}
}

func TestLookup404IsUnknown(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()
	old := BaseURL
	BaseURL = srv.URL
	defer func() { BaseURL = old }()

	found, _, _, err := NewClient("key").Lookup("abc")
	if err != nil || found {
		t.Fatalf("expected found=false err=nil, got found=%v err=%v", found, err)
	}
}

func TestLookupRequiresKey(t *testing.T) {
	if _, _, _, err := NewClient("").Lookup("abc"); err == nil {
		t.Fatal("expected error without API key")
	}
}
