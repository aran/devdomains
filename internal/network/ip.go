package network

import (
	"fmt"
	"log"
	"net"
)

// isLinkLocal checks if an IPv4 address is a link-local address (169.254.x.x)
func isLinkLocal(ip net.IP) bool {
	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 169 && ip4[1] == 254
	}
	return ip.IsLinkLocalUnicast() // For IPv6
}

func GetLocalIPs() ([]net.IP, error) {
	var ips []net.IP

	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("error getting network interfaces: %w", err)
	}

	for _, iface := range interfaces {
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
				if !ip.IsLoopback() && !isLinkLocal(ip) {
					if ipv4 := ip.To4(); ipv4 != nil {
						ips = append(ips, ipv4)
					} else if ip.To16() != nil {
						ips = append(ips, ip)
					}
				}
			}
		}
	}

	if len(ips) == 0 {
		return nil, fmt.Errorf("no usable IP addresses found")
	}

	return ips, nil
}