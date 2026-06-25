package asn

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// Result holds ASN and geolocation data for an IP.
type Result struct {
	IP      string
	Org     string
	Country string
	City    string
}

// ipinfoResponse maps the ipinfo.io JSON response.
type ipinfoResponse struct {
	IP      string `json:"ip"`
	Org     string `json:"org"`
	Country string `json:"country"`
	City    string `json:"city"`
}

// Lookup queries ipinfo.io for ASN and geolocation data for the given IP.
func Lookup(ip string) (Result, error) {
	url := fmt.Sprintf("https://ipinfo.io/%s/json", ip)

	resp, err := http.Get(url)
	if err != nil {
		return Result{}, fmt.Errorf("ipinfo request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return Result{}, fmt.Errorf("ipinfo returned status %d", resp.StatusCode)
	}

	var data ipinfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return Result{}, fmt.Errorf("ipinfo parse error: %w", err)
	}

	return Result{
		IP:      data.IP,
		Org:     data.Org,
		Country: data.Country,
		City:    data.City,
	}, nil
}
