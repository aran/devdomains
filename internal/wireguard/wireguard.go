package wireguard

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/aran/devdomains/internal/output"
)

// Server manages the WireGuard server configuration and lifecycle
type Server struct {
	ctx        context.Context
	workingDir string
	
	// Network configuration
	serverIP   string
	clientIP   string
	cidr       string
	port       int
	
	// Keys
	serverPrivateKey string
	serverPublicKey  string
	clientPrivateKey string
	clientPublicKey  string
	
	// Host network info
	hostIP string
}

// NewServer creates a new WireGuard server instance
func NewServer(ctx context.Context, workingDir string) (*Server, error) {
	// Get primary host IP for endpoint configuration
	hostIP, err := getPrimaryHostIP()
	if err != nil {
		return nil, fmt.Errorf("failed to get host IP: %w", err)
	}
	
	// Use a wireguard subdirectory for all VPN files
	wgDir := filepath.Join(workingDir, "wireguard")
	
	// Create the directory if it doesn't exist
	if err := os.MkdirAll(wgDir, 0755); err != nil {
		return nil, fmt.Errorf("failed to create wireguard directory: %w", err)
	}
	
	return &Server{
		ctx:        ctx,
		workingDir: wgDir,
		cidr:       "10.9.0.0/24",
		serverIP:   "10.9.0.1",
		clientIP:   "10.9.0.2",
		port:       51820,
		hostIP:     hostIP,
	}, nil
}

// Initialize sets up the WireGuard server, loading existing keys or generating new ones
func (s *Server) Initialize() error {
	slog.Info("initializing WireGuard server")
	
	// Check prerequisites
	if err := s.checkPrerequisites(); err != nil {
		return err
	}
	
	// Load or generate keys
	if err := s.loadOrGenerateKeys(); err != nil {
		return fmt.Errorf("failed to setup keys: %w", err)
	}
	
	// Generate server configuration
	if err := s.generateServerConfig(); err != nil {
		return fmt.Errorf("failed to generate server config: %w", err)
	}
	
	// Generate client configuration
	if err := s.generateClientConfig(); err != nil {
		return fmt.Errorf("failed to generate client config: %w", err)
	}
	
	slog.Info("WireGuard server initialized successfully")
	return nil
}

// Start starts the WireGuard interface
func (s *Server) Start() error {
	configPath := filepath.Join(s.workingDir, "wg0.conf")
	
	// Check if interface is already up
	if s.isInterfaceUp() {
		slog.Info("WireGuard interface is already up")
		return nil
	}

	slog.Info("starting WireGuard interface")
	
	// Use wg-quick to bring up the interface
	cmd := exec.CommandContext(s.ctx, "sudo", "wg-quick", "up", configPath)
	cmd.Stdout = output.Stdout
	cmd.Stderr = output.Stdout
	cmd.Stdin = os.Stdin
	
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("failed to start WireGuard: %w", err)
	}

	slog.Info("WireGuard interface started successfully", "ip", s.serverIP)
	return nil
}

// Stop stops the WireGuard interface
func (s *Server) Stop() error {
	configPath := filepath.Join(s.workingDir, "wg0.conf")

	slog.Info("stopping WireGuard interface")

	cmd := exec.CommandContext(s.ctx, "sudo", "wg-quick", "down", configPath)
	cmd.Stdout = output.Stdout
	cmd.Stderr = output.Stdout
	cmd.Stdin = os.Stdin

	if err := cmd.Run(); err != nil {
		slog.Warn("wg-quick down failed", "error", err)
	} else {
		slog.Info("WireGuard interface stopped")
	}

	return nil
}

// GetClientConfig returns the client configuration as a string
func (s *Server) GetClientConfig() (string, error) {
	configPath := filepath.Join(s.workingDir, "wg-client.conf")
	data, err := os.ReadFile(configPath)
	if err != nil {
		return "", fmt.Errorf("failed to read client config: %w", err)
	}
	return string(data), nil
}

// GetServerIP returns the WireGuard server IP address
func (s *Server) GetServerIP() string {
	return s.serverIP
}

// checkPrerequisites checks if WireGuard tools are installed
func (s *Server) checkPrerequisites() error {
	switch runtime.GOOS {
	case "darwin":
		if _, err := exec.LookPath("wg"); err != nil {
			return fmt.Errorf("wireguard-tools not found, install with 'brew install wireguard-tools'")
		}
		if _, err := exec.LookPath("wg-quick"); err != nil {
			return fmt.Errorf("wg-quick not found, install with 'brew install wireguard-tools'")
		}
	case "linux":
		if _, err := exec.LookPath("wg"); err != nil {
			return fmt.Errorf("wireguard-tools not found, install with your package manager")
		}
		if _, err := exec.LookPath("wg-quick"); err != nil {
			return fmt.Errorf("wg-quick not found, install with your package manager")
		}
	default:
		return fmt.Errorf("unsupported operating system: %s", runtime.GOOS)
	}
	return nil
}

// loadOrGenerateKeys loads existing keys or generates new ones
func (s *Server) loadOrGenerateKeys() error {
	serverPrivateKeyPath := filepath.Join(s.workingDir, "wg-server.key")
	serverPublicKeyPath := filepath.Join(s.workingDir, "wg-server.pub")
	clientPrivateKeyPath := filepath.Join(s.workingDir, "wg-client.key")
	clientPublicKeyPath := filepath.Join(s.workingDir, "wg-client.pub")
	
	// Try to load existing keys
	if s.keysExist() {
		slog.Info("loading existing WireGuard keys")
		
		serverPrivate, err := os.ReadFile(serverPrivateKeyPath)
		if err != nil {
			return err
		}
		s.serverPrivateKey = strings.TrimSpace(string(serverPrivate))
		
		serverPublic, err := os.ReadFile(serverPublicKeyPath)
		if err != nil {
			return err
		}
		s.serverPublicKey = strings.TrimSpace(string(serverPublic))
		
		clientPrivate, err := os.ReadFile(clientPrivateKeyPath)
		if err != nil {
			return err
		}
		s.clientPrivateKey = strings.TrimSpace(string(clientPrivate))
		
		clientPublic, err := os.ReadFile(clientPublicKeyPath)
		if err != nil {
			return err
		}
		s.clientPublicKey = strings.TrimSpace(string(clientPublic))

		slog.Info("loaded existing WireGuard keys")
		return nil
	}

	// Generate new keys
	slog.Info("generating new WireGuard keys")
	
	// Generate server keys
	serverPrivate, serverPublic, err := s.generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate server keys: %w", err)
	}
	s.serverPrivateKey = serverPrivate
	s.serverPublicKey = serverPublic
	
	// Generate client keys
	clientPrivate, clientPublic, err := s.generateKeyPair()
	if err != nil {
		return fmt.Errorf("failed to generate client keys: %w", err)
	}
	s.clientPrivateKey = clientPrivate
	s.clientPublicKey = clientPublic
	
	// Save keys
	if err := os.WriteFile(serverPrivateKeyPath, []byte(s.serverPrivateKey), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(serverPublicKeyPath, []byte(s.serverPublicKey), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(clientPrivateKeyPath, []byte(s.clientPrivateKey), 0600); err != nil {
		return err
	}
	if err := os.WriteFile(clientPublicKeyPath, []byte(s.clientPublicKey), 0644); err != nil {
		return err
	}

	slog.Info("generated and saved new WireGuard keys")
	return nil
}

// keysExist checks if all key files exist
func (s *Server) keysExist() bool {
	files := []string{
		"wg-server.key",
		"wg-server.pub",
		"wg-client.key",
		"wg-client.pub",
	}
	
	for _, file := range files {
		path := filepath.Join(s.workingDir, file)
		if _, err := os.Stat(path); os.IsNotExist(err) {
			return false
		}
	}
	
	return true
}

// generateKeyPair generates a WireGuard private/public key pair
func (s *Server) generateKeyPair() (string, string, error) {
	// Generate private key
	cmd := exec.CommandContext(s.ctx, "wg", "genkey")
	privateKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate private key: %w", err)
	}
	privateKey := strings.TrimSpace(string(privateKeyBytes))
	
	// Generate public key from private key
	cmd = exec.CommandContext(s.ctx, "wg", "pubkey")
	cmd.Stdin = strings.NewReader(privateKey)
	publicKeyBytes, err := cmd.Output()
	if err != nil {
		return "", "", fmt.Errorf("failed to generate public key: %w", err)
	}
	publicKey := strings.TrimSpace(string(publicKeyBytes))
	
	return privateKey, publicKey, nil
}

// generateServerConfig generates the server WireGuard configuration
func (s *Server) generateServerConfig() error {
	config := fmt.Sprintf(`[Interface]
Address = %s/24
ListenPort = %d
PrivateKey = %s

[Peer]
PublicKey = %s
AllowedIPs = %s/32
`, s.serverIP, s.port, s.serverPrivateKey, s.clientPublicKey, s.clientIP)
	
	configPath := filepath.Join(s.workingDir, "wg0.conf")
	if err := os.WriteFile(configPath, []byte(config), 0600); err != nil {
		return fmt.Errorf("failed to write server config: %w", err)
	}

	slog.Info("generated WireGuard server configuration")
	return nil
}

// generateClientConfig generates the client WireGuard configuration
func (s *Server) generateClientConfig() error {
	config := fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s/24
DNS = %s

[Peer]
PublicKey = %s
AllowedIPs = %s
Endpoint = %s:%d
PersistentKeepalive = 25
`, s.clientPrivateKey, s.clientIP, s.serverIP, s.serverPublicKey, s.cidr, s.hostIP, s.port)
	
	configPath := filepath.Join(s.workingDir, "wg-client.conf")
	if err := os.WriteFile(configPath, []byte(config), 0644); err != nil {
		return fmt.Errorf("failed to write client config: %w", err)
	}

	slog.Info("generated WireGuard client configuration")
	return nil
}

// isInterfaceUp checks if the WireGuard interface is up
func (s *Server) isInterfaceUp() bool {
	cmd := exec.CommandContext(s.ctx, "sudo", "wg", "show", "wg0")
	err := cmd.Run()
	return err == nil
}

// getDefaultInterface gets the default network interface name
func (s *Server) getDefaultInterface() string {
	// Try to get the default route interface
	cmd := exec.Command("sh", "-c", "ip route | grep default | awk '{print $5}' | head -1")
	output, err := cmd.Output()
	if err == nil {
		iface := strings.TrimSpace(string(output))
		if iface != "" {
			return iface
		}
	}
	
	// Fallback to common interface names
	switch runtime.GOOS {
	case "darwin":
		return "en0"
	case "linux":
		// Check for common interface names
		interfaces := []string{"eth0", "ens4", "ens3", "enp0s3", "wlan0"}
		for _, iface := range interfaces {
			if _, err := net.InterfaceByName(iface); err == nil {
				return iface
			}
		}
		return "eth0"
	default:
		return "eth0"
	}
}

// getPrimaryHostIP gets the primary LAN IP of the host
func getPrimaryHostIP() (string, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	
	// Collect all valid IPs
	var ips []net.IP
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
				if ipv4 := ipnet.IP.To4(); ipv4 != nil {
					// Skip link-local addresses
					if ipv4[0] == 169 && ipv4[1] == 254 {
						continue
					}
					ips = append(ips, ipv4)
				}
			}
		}
	}
	
	if len(ips) == 0 {
		return "", fmt.Errorf("no suitable IP addresses found")
	}
	
	// Prioritize common private network ranges
	for _, ip := range ips {
		if ip[0] == 192 && ip[1] == 168 {
			return ip.String(), nil
		}
	}
	
	for _, ip := range ips {
		if ip[0] == 10 {
			return ip.String(), nil
		}
	}
	
	for _, ip := range ips {
		if ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31 {
			return ip.String(), nil
		}
	}
	
	// Return first available IP
	return ips[0].String(), nil
}