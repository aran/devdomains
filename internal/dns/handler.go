package dns

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"

	"github.com/aran/mdns-caddy/internal/network"
	"github.com/miekg/dns"
)

// DoHHandler creates an HTTP handler for DNS-over-HTTPS requests
// targetDomain is the domain to resolve to the local IP
func DoHHandler(targetDomain string) http.HandlerFunc {
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
		resp, err := handleDNSQuery(msg, targetDomain)
		if err != nil {
			log.Printf("Error handling DNS query: %v", err)
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

// handleDNSQuery processes DNS queries and returns the appropriate response
func handleDNSQuery(query *dns.Msg, targetDomain string) (*dns.Msg, error) {
	response := new(dns.Msg)
	response.SetReply(query)
	response.Authoritative = true

	// Process each question
	for _, q := range query.Question {
		qname := strings.TrimSuffix(q.Name, ".")
		
		// Check if this is a request for our target domain or subdomain
		if qname == targetDomain || strings.HasSuffix(qname, "."+targetDomain) {
			// Get local machine IPs
			ips, err := network.GetLocalIPs()
			if err != nil {
				return nil, fmt.Errorf("error getting local IPs: %w", err)
			}

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
						break // Only include one answer for simplicity
					}
				}
			}
		} else {
			// For non-target domains, we should refuse to answer
			// This is important as the profile is configured to only ask us about specific domains
			response.Rcode = dns.RcodeRefused
		}
	}

	return response, nil
}