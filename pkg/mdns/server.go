// Package mdns provides utilities for mDNS server configuration and management
package mdns

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/aran/mdns-caddy/pkg/network"
	"github.com/hashicorp/mdns"
)

// ServiceConfig contains configuration for mDNS service advertising
type ServiceConfig struct {
	Name     string // Instance name
	Type     string // Service type
	Domain   string // Domain
	Hostname string // Host with .local suffix for mDNS
	Port     int    // Port
}

// DefaultServiceConfig provides default values for mDNS service configuration
var DefaultServiceConfig = ServiceConfig{
	Name:     "back",
	Type:     "_http._tcp",
	Domain:   "local.",
	Hostname: "back.local.",
}

// SetupServer configures and starts an mDNS server with the given configuration
func SetupServer(config ServiceConfig) (*mdns.Server, error) {
	// Get local IP addresses
	ips, err := network.GetLocalIPs()
	if err != nil {
		return nil, fmt.Errorf("error getting local IPs: %w", err)
	}

	sysHostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("error getting hostname: %w", err)
	}

	// Create an HTTP service for service discovery
	service, err := mdns.NewMDNSService(
		config.Name,          // Instance name
		config.Type,          // Service type
		config.Domain,        // Domain
		config.Hostname,      // Host with .local suffix for mDNS
		config.Port,          // Port
		ips,                  // IP addresses
		[]string{"txtv=0"},   // TXT records
	)
	if err != nil {
		return nil, fmt.Errorf("error creating mDNS service: %w", err)
	}

	// Create the mDNS server with the HTTP service
	server, err := mdns.NewServer(&mdns.Config{
		Zone: service,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating mDNS server: %w", err)
	}

	// Categorize IPs for better logging
	var ipv4s, ipv6s []net.IP
	for _, ip := range ips {
		if ip.To4() != nil {
			ipv4s = append(ipv4s, ip)
		} else {
			ipv6s = append(ipv6s, ip)
		}
	}

	log.Printf("mDNS server started, advertising:")
	log.Printf("- Service: %s.%s.%s", config.Name, config.Type, config.Domain)
	log.Printf("- Hostname: %s", config.Hostname[:len(config.Hostname)-1]) // Remove trailing dot for display
	log.Printf("- Port: %d", config.Port)
	log.Printf("- IPv4 Addresses (A records): %v", ipv4s)
	log.Printf("- IPv6 Addresses (AAAA records): %v", ipv6s)
	log.Printf("- System hostname: %s", sysHostname)

	return server, nil
}

// GetServiceHostnames returns hostnames for the service in a format suitable for Caddy
func GetServiceHostnames(config ServiceConfig) []string {
	// Return only the "back.local" hostname, removing trailing dot if present
	hostname := config.Hostname
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	return []string{hostname}
}