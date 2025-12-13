package dns

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/miekg/dns"
)

// SelfTestOptions provides configuration for the DNS-over-HTTPS self-test
type SelfTestOptions struct {
	// The target domain to query
	TargetDomain string
	// The server hostname to use (e.g., "back.local")
	ServerHostname string
	// The server port to use
	ServerPort int
	// Path to the root CA certificate file
	RootCAPath string
}

// RunSelfTest performs a DNS-over-HTTPS self-test using the target domain on the local server
func RunSelfTest(opts SelfTestOptions) error {
	// If any options are missing, return an error
	if opts.TargetDomain == "" {
		return fmt.Errorf("target domain not specified for self-test")
	}
	if opts.ServerHostname == "" {
		return fmt.Errorf("server hostname not specified for self-test")
	}
	if opts.ServerPort == 0 {
		return fmt.Errorf("server port not specified for self-test")
	}
	
	// Log that we're starting a self-test
	slog.Info("running DNS-over-HTTPS self-test", "domain", opts.TargetDomain)
	
	// Ensure the domain ends with a dot as required by DNS
	queryDomain := opts.TargetDomain
	if !strings.HasSuffix(queryDomain, ".") {
		queryDomain = queryDomain + "."
	}
	
	// Create a DNS message with an A record query for the target domain
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{Name: queryDomain, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	
	// Pack the DNS message
	buf, err := m.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS message: %w", err)
	}
	
	// Create the base64 encoded query parameter for GET request
	b64 := base64.URLEncoding.EncodeToString(buf)
	b64 = strings.TrimRight(b64, "=") // Remove padding for URL safety
	
	// Construct the request URL
	requestURL := fmt.Sprintf("https://%s:%d/dns-query?dns=%s", 
		opts.ServerHostname, opts.ServerPort, b64)
	
	// Setup a TLS config that trusts our local root CA
	tlsConfig, err := createTLSConfig(opts.RootCAPath)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}
	
	// Create an HTTP client with our TLS config
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	// Make the request
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	req.Header.Set("Accept", "application/dns-message")
	
	// Execute the request
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DNS-over-HTTPS request failed: %w", err)
	}
	defer resp.Body.Close()
	
	duration := time.Since(startTime)
	
	// Check if the response was successful
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNS-over-HTTPS request returned non-OK status: %d", resp.StatusCode)
	}
	
	// Check content type
	if !strings.Contains(resp.Header.Get("Content-Type"), "application/dns-message") {
		return fmt.Errorf("DNS-over-HTTPS response has wrong content type: %s",
			resp.Header.Get("Content-Type"))
	}
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read DNS-over-HTTPS response: %w", err)
	}
	
	// Parse the DNS response
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return fmt.Errorf("failed to unpack DNS response: %w", err)
	}
	
	// Check if we got a valid response
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query returned error code: %s", 
			dns.RcodeToString[response.Rcode])
	}
	
	// Check if we have any answers
	if len(response.Answer) == 0 {
		return fmt.Errorf("DNS query returned no answers")
	}
	
	// Get IP addresses from the response
	var ips []string
	for _, answer := range response.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	
	if len(ips) == 0 {
		return fmt.Errorf("DNS query returned no IP addresses")
	}
	
	// Log success result
	slog.Info("self-test SUCCESS: DNS-over-HTTPS query completed",
		"domain", opts.TargetDomain,
		"duration_ms", float64(duration.Microseconds())/1000.0,
		"answers", len(response.Answer),
		"ips", strings.Join(ips, ", "))
	
	// Also test with an unsupported query type
	RunSelfTestUnsupportedType(opts)
	
	return nil
}

// RunSelfTestUnsupportedType tests that the server correctly handles unsupported DNS record types
func RunSelfTestUnsupportedType(opts SelfTestOptions) error {
	if opts.TargetDomain == "" || opts.ServerHostname == "" || opts.ServerPort == 0 {
		return fmt.Errorf("missing required options for unsupported type self-test")
	}
	
	// Log that we're starting a self-test for an unsupported record type
	slog.Info("running DNS-over-HTTPS self-test for unsupported record type", "domain", opts.TargetDomain)
	
	// Ensure the domain ends with a dot as required by DNS
	queryDomain := opts.TargetDomain
	if !strings.HasSuffix(queryDomain, ".") {
		queryDomain = queryDomain + "."
	}
	
	// Create a DNS message with a TXT record query (which we don't support)
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{Name: queryDomain, Qtype: dns.TypeTXT, Qclass: dns.ClassINET},
	}
	
	// Pack the DNS message
	buf, err := m.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS message for unsupported type test: %w", err)
	}
	
	// Construct the request URL
	requestURL := fmt.Sprintf("https://%s:%d/dns-query", 
		opts.ServerHostname, opts.ServerPort)
	
	// Setup a TLS config that trusts our local root CA
	tlsConfig, err := createTLSConfig(opts.RootCAPath)
	if err != nil {
		return fmt.Errorf("failed to create TLS config for unsupported type test: %w", err)
	}
	
	// Create an HTTP client with our TLS config
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	// Make the request
	req, err := http.NewRequest("POST", requestURL, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request for unsupported type test: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	
	// Execute the request
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DNS-over-HTTPS request for unsupported type failed: %w", err)
	}
	defer resp.Body.Close()
	
	duration := time.Since(startTime)
	
	// Check if the response was successful
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNS-over-HTTPS request for unsupported type returned non-OK status: %d", 
			resp.StatusCode)
	}
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read DNS-over-HTTPS response for unsupported type: %w", err)
	}
	
	// Parse the DNS response
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return fmt.Errorf("failed to unpack DNS response for unsupported type: %w", err)
	}
	
	// For unsupported types, we expect NOERROR with empty answer section
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query for unsupported type returned wrong code: %s (expected NOERROR)", 
			dns.RcodeToString[response.Rcode])
	}
	
	// Verify empty answer section
	if len(response.Answer) > 0 {
		return fmt.Errorf("DNS query for unsupported type unexpectedly returned %d answers", 
			len(response.Answer))
	}
	
	// Log success result
	slog.Info("self-test SUCCESS: unsupported record type (TXT) query completed",
		"domain", opts.TargetDomain,
		"duration_ms", float64(duration.Microseconds())/1000.0,
		"result", "NOERROR with empty answer section")
	
	return nil
}

// Try the self-test with a POST request which is more common for DoH
func RunSelfTestPost(opts SelfTestOptions) error {
	if opts.TargetDomain == "" || opts.ServerHostname == "" || opts.ServerPort == 0 {
		return fmt.Errorf("missing required options for self-test")
	}
	
	// Log that we're starting a self-test
	slog.Info("running DNS-over-HTTPS self-test (POST method)", "domain", opts.TargetDomain)
	
	// Ensure the domain ends with a dot as required by DNS
	queryDomain := opts.TargetDomain
	if !strings.HasSuffix(queryDomain, ".") {
		queryDomain = queryDomain + "."
	}
	
	// Create a DNS message with an A record query for the target domain
	m := new(dns.Msg)
	m.Id = dns.Id()
	m.RecursionDesired = true
	m.Question = []dns.Question{
		{Name: queryDomain, Qtype: dns.TypeA, Qclass: dns.ClassINET},
	}
	
	// Pack the DNS message
	buf, err := m.Pack()
	if err != nil {
		return fmt.Errorf("failed to pack DNS message: %w", err)
	}
	
	// Construct the request URL
	requestURL := fmt.Sprintf("https://%s:%d/dns-query", 
		opts.ServerHostname, opts.ServerPort)
	
	// Setup a TLS config that trusts our local root CA
	tlsConfig, err := createTLSConfig(opts.RootCAPath)
	if err != nil {
		return fmt.Errorf("failed to create TLS config: %w", err)
	}
	
	// Create an HTTP client with our TLS config
	client := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
	
	// Make the request
	req, err := http.NewRequest("POST", requestURL, bytes.NewReader(buf))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}
	
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	
	// Execute the request
	startTime := time.Now()
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("DNS-over-HTTPS POST request failed: %w", err)
	}
	defer resp.Body.Close()
	
	duration := time.Since(startTime)
	
	// Check if the response was successful
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("DNS-over-HTTPS POST request returned non-OK status: %d", resp.StatusCode)
	}
	
	// Read the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read DNS-over-HTTPS response: %w", err)
	}
	
	// Parse the DNS response
	response := new(dns.Msg)
	if err := response.Unpack(body); err != nil {
		return fmt.Errorf("failed to unpack DNS response: %w", err)
	}
	
	// Check if we got a valid response
	if response.Rcode != dns.RcodeSuccess {
		return fmt.Errorf("DNS query returned error code: %s", 
			dns.RcodeToString[response.Rcode])
	}
	
	// Check if we have any answers
	if len(response.Answer) == 0 {
		return fmt.Errorf("DNS query returned no answers")
	}
	
	// Get IP addresses from the response
	var ips []string
	for _, answer := range response.Answer {
		switch rr := answer.(type) {
		case *dns.A:
			ips = append(ips, rr.A.String())
		case *dns.AAAA:
			ips = append(ips, rr.AAAA.String())
		}
	}
	
	if len(ips) == 0 {
		return fmt.Errorf("DNS query returned no IP addresses")
	}
	
	// Log success result
	slog.Info("self-test POST SUCCESS: DNS-over-HTTPS query completed",
		"domain", opts.TargetDomain,
		"duration_ms", float64(duration.Microseconds())/1000.0,
		"answers", len(response.Answer),
		"ips", strings.Join(ips, ", "))
	
	return nil
}

// createTLSConfig creates a TLS config that trusts the supplied root CA
func createTLSConfig(rootCAPath string) (*tls.Config, error) {
	// Load root CA certificate
	rootCAPEM, err := os.ReadFile(rootCAPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read root CA certificate: %w", err)
	}
	
	// Create a cert pool and add the root CA
	roots := x509.NewCertPool()
	if ok := roots.AppendCertsFromPEM(rootCAPEM); !ok {
		return nil, fmt.Errorf("failed to parse root CA certificate")
	}
	
	// Create a TLS config with the cert pool
	return &tls.Config{
		RootCAs: roots,
		// For testing purposes, we'll use a more liberal policy for hostname verification
		InsecureSkipVerify: false,
	}, nil
}