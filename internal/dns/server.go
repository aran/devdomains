package dns

import (
	"fmt"
	"log/slog"
	"net"
	"strings"

	"github.com/aran/devdomains/internal/network"
	"github.com/miekg/dns"
)

// Server represents a DNS server that resolves configured domains to local IPs
type Server struct {
	domains   []string
	server    *dns.Server
	port      int
	address   string // Optional specific address to bind to
	upstreams []string
}

// NewServer creates a new DNS server
func NewServer(domains []string, port int) *Server {
	return &Server{
		domains: domains,
		port:    port,
		upstreams: []string{
			"8.8.8.8:53",     // Google DNS
			"8.8.4.4:53",     // Google DNS secondary
			"1.1.1.1:53",     // Cloudflare DNS
		},
	}
}

// NewServerWithAddress creates a new DNS server that binds to a specific address
func NewServerWithAddress(domains []string, address string, port int) *Server {
	return &Server{
		domains: domains,
		port:    port,
		address: address,
		upstreams: []string{
			"8.8.8.8:53",     // Google DNS
			"8.8.4.4:53",     // Google DNS secondary
			"1.1.1.1:53",     // Cloudflare DNS
		},
	}
}

// NewServerWithUpstreams creates a new DNS server with custom upstream servers
func NewServerWithUpstreams(domains []string, port int, upstreams []string) *Server {
	if len(upstreams) == 0 {
		return NewServer(domains, port)
	}
	return &Server{
		domains:   domains,
		port:      port,
		upstreams: upstreams,
	}
}

// Start starts the DNS UDP server
func (s *Server) Start() error {
	// Create DNS server handler
	dns.HandleFunc(".", s.handleDNSRequest)

	// Configure the server
	addr := fmt.Sprintf(":%d", s.port)
	if s.address != "" {
		addr = fmt.Sprintf("%s:%d", s.address, s.port)
	}
	
	s.server = &dns.Server{
		Addr: addr,
		Net:  "udp",
	}

	slog.Info("starting DNS server", "addr", addr, "protocol", "UDP")
	slog.Info("DNS server will resolve domains", "domains", strings.Join(s.domains, ", "))

	// Start the server in a goroutine
	go func() {
		if err := s.server.ListenAndServe(); err != nil {
			slog.Error("DNS server error", "error", err)
		}
	}()

	return nil
}

// Stop gracefully stops the DNS server
func (s *Server) Stop() error {
	if s.server != nil {
		return s.server.Shutdown()
	}
	return nil
}

// handleDNSRequest processes incoming DNS queries
func (s *Server) handleDNSRequest(w dns.ResponseWriter, r *dns.Msg) {
	// Use the same resolution logic as DoH, with our configured upstreams
	response, err := handleDNSQueryWithUpstreams(r, s.domains, s.upstreams)
	if err != nil {
		slog.Error("DNS server error handling query", "error", err)
		// Send a SERVFAIL response
		m := new(dns.Msg)
		m.SetReply(r)
		m.Rcode = dns.RcodeServerFailure
		w.WriteMsg(m)
		return
	}

	// Send the response
	if err := w.WriteMsg(response); err != nil {
		slog.Error("DNS server error writing response", "error", err)
	}
}

// handleDNSRequestTCP handles TCP DNS requests (optional but good to have)
func (s *Server) handleDNSRequestTCP(w dns.ResponseWriter, r *dns.Msg) {
	s.handleDNSRequest(w, r)
}

// StartTCP starts an additional TCP DNS server on the same port
func (s *Server) StartTCP() error {
	tcpServer := &dns.Server{
		Addr: fmt.Sprintf(":%d", s.port),
		Net:  "tcp",
	}

	slog.Info("starting DNS server", "port", s.port, "protocol", "TCP")

	go func() {
		if err := tcpServer.ListenAndServe(); err != nil {
			slog.Error("DNS TCP server error", "error", err)
		}
	}()

	return nil
}

// GetLocalDNSAddresses returns the DNS server addresses that clients can use
func (s *Server) GetLocalDNSAddresses() ([]string, error) {
	ips, err := network.GetLocalIPs()
	if err != nil {
		return nil, err
	}

	var addresses []string
	for _, ip := range ips {
		// Only include IPv4 for simplicity
		if ip.To4() != nil {
			addresses = append(addresses, fmt.Sprintf("%s:%d", ip.String(), s.port))
		}
	}

	return addresses, nil
}

// TestResolution performs a local test of DNS resolution
func (s *Server) TestResolution(domain string) error {
	// Create a test query
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeA)

	// Resolve using our handler with configured upstreams
	response, err := handleDNSQueryWithUpstreams(m, s.domains, s.upstreams)
	if err != nil {
		return fmt.Errorf("resolution failed: %w", err)
	}

	if len(response.Answer) == 0 {
		return fmt.Errorf("no answers returned for %s", domain)
	}

	// Check if we got an A record
	for _, ans := range response.Answer {
		if a, ok := ans.(*dns.A); ok {
			slog.Debug("DNS test resolution", "domain", domain, "ip", a.A.String())
			return nil
		}
	}

	return fmt.Errorf("no A records in response for %s", domain)
}

// IsListening checks if the DNS server is listening on its port
func (s *Server) IsListening() bool {
	conn, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", s.port))
	if err != nil {
		return false
	}
	conn.Close()
	return true
}