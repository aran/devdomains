package mdns

import (
	"fmt"
	"log"
	"net"
	"os"

	"github.com/aran/devdomains/internal/network"
	"github.com/hashicorp/mdns"
)

type ServiceConfig struct {
	Name     string // Instance name
	Type     string // Service type
	Domain   string // Domain
	Hostname string // Host with .local suffix for mDNS
	Port     int    // Port
}

var DefaultServiceConfig = ServiceConfig{
	Name:     "back",
	Type:     "_http._tcp",
	Domain:   "local.",
	Hostname: "back.local.",
}

func SetupServer(config ServiceConfig) (*mdns.Server, error) {
	ips, err := network.GetLocalIPs()
	if err != nil {
		return nil, fmt.Errorf("error getting local IPs: %w", err)
	}

	sysHostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("error getting hostname: %w", err)
	}

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

	server, err := mdns.NewServer(&mdns.Config{
		Zone: service,
	})
	if err != nil {
		return nil, fmt.Errorf("error creating mDNS server: %w", err)
	}

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

func GetServiceHostnames(config ServiceConfig) []string {
	hostname := config.Hostname
	if len(hostname) > 0 && hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}
	return []string{hostname}
}