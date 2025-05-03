// Package network provides networking utilities for the application
package network

import (
	"fmt"
	"log"
	"net"
)

// GetLocalIPs returns a slice of local non-loopback IPv4 and IPv6 addresses
func GetLocalIPs() ([]net.IP, error) {
	var ips []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting network interfaces: %w", err)
	}

	for _, iface := range interfaces {
		// Skip loopback and non-up interfaces
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			log.Printf("Error getting addresses for interface %s: %v", iface.Name, err)
			continue
		}

		for _, addr := range addrs {
			switch v := addr.(type) {
			case *net.IPNet:
				ip := v.IP
				if !ip.IsLoopback() {
					// For IPv4 addresses, To4() returns a 4-byte representation
					// For IPv6 addresses, To4() returns nil and we use the original address
					if ipv4 := ip.To4(); ipv4 != nil {
						ips = append(ips, ipv4)
					} else if ip.To16() != nil {
						// Native IPv6 address (already filtered loopback above)
						ips = append(ips, ip)
					}
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no non-loopback IP addresses found")
	}

	return ips, nil
}