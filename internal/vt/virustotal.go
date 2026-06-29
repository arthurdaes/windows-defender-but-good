// Package vt is a minimal VirusTotal API v3 client. It only ever looks files up
// by hash (sends the hash, never the file) for the core flow.
package vt

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// BaseURL is overridable in tests.
var BaseURL = "https://www.virustotal.com/api/v3"

type Client struct {
	APIKey string
	HTTP   *http.Client
}

func NewClient(key string) *Client {
	return &Client{APIKey: key, HTTP: &http.Client{Timeout: 30 * time.Second}}
}

type stats struct {
	Malicious  int `json:"malicious"`
	Suspicious int `json:"suspicious"`
	Harmless   int `json:"harmless"`
	Undetected int `json:"undetected"`
	Timeout    int `json:"timeout"`
}

type response struct {
	Data struct {
		Attributes struct {
			LastAnalysisStats stats `json:"last_analysis_stats"`
		} `json:"attributes"`
	} `json:"data"`
}

// Lookup returns (found, malicious, total, err). found=false on a 404 (VT has
// never seen the hash — "unknown", not an error). Retries on HTTP 429.
func (c *Client) Lookup(sha256 string) (bool, int, int, error) {
	if c.APIKey == "" {
		return false, 0, 0, fmt.Errorf("no VirusTotal API key configured")
	}
	url := BaseURL + "/files/" + sha256
	for attempt := 0; attempt < 3; attempt++ {
		req, _ := http.NewRequest(http.MethodGet, url, nil)
		req.Header.Set("x-apikey", c.APIKey)
		resp, err := c.HTTP.Do(req)
		if err != nil {
			return false, 0, 0, fmt.Errorf("network error contacting VirusTotal: %w", err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		switch resp.StatusCode {
		case http.StatusOK:
			var r response
			if err := json.Unmarshal(body, &r); err != nil {
				return false, 0, 0, err
			}
			s := r.Data.Attributes.LastAnalysisStats
			mal := s.Malicious + s.Suspicious
			total := s.Malicious + s.Suspicious + s.Harmless + s.Undetected + s.Timeout
			return true, mal, total, nil
		case http.StatusNotFound:
			return false, 0, 0, nil
		case http.StatusUnauthorized:
			return false, 0, 0, fmt.Errorf("VirusTotal rejected the API key (401)")
		case http.StatusTooManyRequests:
			if attempt < 2 {
				time.Sleep(time.Duration(20*(attempt+1)) * time.Second)
				continue
			}
			return false, 0, 0, fmt.Errorf("VirusTotal rate limit exceeded (429)")
		default:
			return false, 0, 0, fmt.Errorf("VirusTotal returned HTTP %d", resp.StatusCode)
		}
	}
	return false, 0, 0, fmt.Errorf("VirusTotal lookup failed after retries")
}
