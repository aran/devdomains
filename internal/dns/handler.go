package dns

import (
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/aran/devdomains/internal/network"
	"github.com/miekg/dns"
)

// DoHHandler creates an HTTP handler for DNS-over-HTTPS requests for a single domain
// targetDomain is the domain to resolve to the local IP
func DoHHandler(targetDomain string) http.HandlerFunc {
	return DoHHandlerMulti([]string{targetDomain})
}

// DoHHandlerMulti creates an HTTP handler for DNS-over-HTTPS requests for multiple domains
// targetDomains is a list of domains to resolve to the local IP
func DoHHandlerMulti(targetDomains []string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodPost {
			http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
			return
		}

		var msg *dns.Msg
		var err error

		switch r.Method {
		case http.MethodGet:
			// Handle GET requests with ?dns=base64_encoded_query
			dnsParam := r.URL.Query().Get("dns")
			if dnsParam == "" {
				http.Error(w, "Missing 'dns' parameter", http.StatusBadRequest)
				return
			}

			// The base64 might be URL-encoded, so handle that
			dnsParam = strings.ReplaceAll(dnsParam, "-", "+")
			dnsParam = strings.ReplaceAll(dnsParam, "_", "/")
			// Pad with = if needed
			if mod := len(dnsParam) % 4; mod != 0 {
				dnsParam += strings.Repeat("=", 4-mod)
			}

			wireMsg, err := base64.StdEncoding.DecodeString(dnsParam)
			if err != nil {
				http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
				return
			}

			msg = &dns.Msg{}
			if err := msg.Unpack(wireMsg); err != nil {
				http.Error(w, "Invalid DNS message", http.StatusBadRequest)
				return
			}

		case http.MethodPost:
			// Handle POST requests with wire format DNS query in body
			contentType := r.Header.Get("Content-Type")
			if contentType != "application/dns-message" {
				http.Error(w, "Content-Type must be application/dns-message", http.StatusBadRequest)
				return
			}

			body, err := io.ReadAll(r.Body)
			if err != nil {
				http.Error(w, "Error reading request body", http.StatusBadRequest)
				return
			}

			msg = &dns.Msg{}
			if err := msg.Unpack(body); err != nil {
				http.Error(w, "Invalid DNS message", http.StatusBadRequest)
				return
			}
		}

		// Get response message
		resp, err := handleDNSQueryMulti(msg, targetDomains)
		if err != nil {
			slog.Error("error handling DNS query", "error", err)
			http.Error(w, "DNS resolution error", http.StatusInternalServerError)
			return
		}

		// Pack the response
		wireResp, err := resp.Pack()
		if err != nil {
			http.Error(w, "Error encoding response", http.StatusInternalServerError)
			return
		}

		// Return response
		w.Header().Set("Content-Type", "application/dns-message")
		w.Write(wireResp)
	}
}

// handleDNSQueryMulti processes DNS queries for multiple domains and returns the appropriate response
func handleDNSQueryMulti(query *dns.Msg, targetDomains []string) (*dns.Msg, error) {
	// Process each question
	for _, q := range query.Question {
		qname := strings.TrimSuffix(q.Name, ".")

		// Log the DNS query
		slog.Debug("DNS query", "type", dns.TypeToString[q.Qtype], "name", q.Name)

		// Check if this is a request for one of our target domains or their subdomains
		matchedDomain := ""
		for _, domain := range targetDomains {
			if qname == domain || strings.HasSuffix(qname, "."+domain) {
				matchedDomain = domain
				break
			}
		}

		if matchedDomain != "" {
			// Handle locally configured domains
			response := new(dns.Msg)
			response.SetReply(query)
			response.Authoritative = true
			
			// Get local machine IPs
			ips, err := network.GetLocalIPs()
			if err != nil {
				return nil, fmt.Errorf("error getting local IPs: %w", err)
			}

			// Keep track of whether we handled this query type
			handled := false

			switch q.Qtype {
			case dns.TypeA:
				// Find an IPv4 address to return
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    60, // short TTL for development
							},
							A: ipv4,
						}
						response.Answer = append(response.Answer, rr)
						slog.Debug("DNS response", "type", "A", "name", q.Name, "ip", ipv4.String())
						handled = true
						break // Only include one answer for simplicity
					}
				}

			case dns.TypeAAAA:
				// Find an IPv6 address to return
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 == nil && ip.To16() != nil {
						rr := &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    60, // short TTL for development
							},
							AAAA: ip,
						}
						response.Answer = append(response.Answer, rr)
						slog.Debug("DNS response", "type", "AAAA", "name", q.Name, "ip", ip.String())
						handled = true
						break // Only include one answer for simplicity
					}
				}
			default:
				// For unsupported record types, we return NOERROR with empty answer section
				// This is the correct behavior according to RFC 1035 for authoritative servers
				slog.Debug("DNS query for unsupported type", "type", dns.TypeToString[q.Qtype], "code", q.Qtype, "name", q.Name)
				// response.Rcode is already NOERROR (0) by default
			}

			if !handled {
				slog.Debug("DNS response NOERROR with empty answer", "name", q.Name, "type", dns.TypeToString[q.Qtype])
			}
			
			return response, nil
		}
	}

	// For non-target domains, forward to upstream DNS
	return forwardToUpstream(query)
}

// forwardToUpstream forwards DNS queries to upstream DNS servers
func forwardToUpstream(query *dns.Msg) (*dns.Msg, error) {
	// Default upstream DNS servers
	upstreams := []string{
		"8.8.8.8:53",     // Google DNS
		"8.8.4.4:53",     // Google DNS secondary
		"1.1.1.1:53",     // Cloudflare DNS
	}
	
	return forwardToUpstreamServers(query, upstreams)
}

// forwardToUpstreamServers forwards DNS queries to specified upstream DNS servers
func forwardToUpstreamServers(query *dns.Msg, upstreams []string) (*dns.Msg, error) {
	client := new(dns.Client)
	client.Timeout = 5 * time.Second

	// Try each upstream server until one works
	for _, upstream := range upstreams {
		resp, _, err := client.Exchange(query, upstream)
		if err == nil && resp != nil {
			if len(query.Question) > 0 {
				slog.Debug("DNS response forwarded", "name", query.Question[0].Name, "upstream", upstream)
			}
			return resp, nil
		}
		if err != nil {
			slog.Debug("DNS upstream failed", "upstream", upstream, "error", err)
		}
	}

	// If all upstreams fail, return SERVFAIL
	response := new(dns.Msg)
	response.SetReply(query)
	response.Rcode = dns.RcodeServerFailure
	return response, fmt.Errorf("all upstream DNS servers failed")
}

// handleDNSQueryWithUpstreams processes DNS queries with custom upstream servers
func handleDNSQueryWithUpstreams(query *dns.Msg, targetDomains []string, upstreams []string) (*dns.Msg, error) {
	// Process each question
	for _, q := range query.Question {
		qname := strings.TrimSuffix(q.Name, ".")

		// Log the DNS query
		slog.Debug("DNS query", "type", dns.TypeToString[q.Qtype], "name", q.Name)

		// Check if this is a request for one of our target domains or their subdomains
		matchedDomain := ""
		for _, domain := range targetDomains {
			if qname == domain || strings.HasSuffix(qname, "."+domain) {
				matchedDomain = domain
				break
			}
		}

		if matchedDomain != "" {
			// Handle locally configured domains
			response := new(dns.Msg)
			response.SetReply(query)
			response.Authoritative = true
			
			// Get local machine IPs
			ips, err := network.GetLocalIPs()
			if err != nil {
				return nil, fmt.Errorf("error getting local IPs: %w", err)
			}

			// Keep track of whether we handled this query type
			handled := false

			switch q.Qtype {
			case dns.TypeA:
				// Find an IPv4 address to return
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 != nil {
						rr := &dns.A{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeA,
								Class:  dns.ClassINET,
								Ttl:    60, // short TTL for development
							},
							A: ipv4,
						}
						response.Answer = append(response.Answer, rr)
						slog.Debug("DNS response", "type", "A", "name", q.Name, "ip", ipv4.String())
						handled = true
						break // Only include one answer for simplicity
					}
				}

			case dns.TypeAAAA:
				// Find an IPv6 address to return
				for _, ip := range ips {
					if ipv4 := ip.To4(); ipv4 == nil && ip.To16() != nil {
						rr := &dns.AAAA{
							Hdr: dns.RR_Header{
								Name:   q.Name,
								Rrtype: dns.TypeAAAA,
								Class:  dns.ClassINET,
								Ttl:    60, // short TTL for development
							},
							AAAA: ip,
						}
						response.Answer = append(response.Answer, rr)
						slog.Debug("DNS response", "type", "AAAA", "name", q.Name, "ip", ip.String())
						handled = true
						break // Only include one answer for simplicity
					}
				}
			default:
				// For unsupported record types, we return NOERROR with empty answer section
				// This is the correct behavior according to RFC 1035 for authoritative servers
				slog.Debug("DNS query for unsupported type", "type", dns.TypeToString[q.Qtype], "code", q.Qtype, "name", q.Name)
				// response.Rcode is already NOERROR (0) by default
			}

			if !handled {
				slog.Debug("DNS response NOERROR with empty answer", "name", q.Name, "type", dns.TypeToString[q.Qtype])
			}
			
			return response, nil
		}
	}

	// For non-target domains, forward to upstream DNS
	return forwardToUpstreamServers(query, upstreams)
}

// handleDNSQuery processes DNS queries for a single domain - maintained for backward compatibility
func handleDNSQuery(query *dns.Msg, targetDomain string) (*dns.Msg, error) {
	return handleDNSQueryMulti(query, []string{targetDomain})
}