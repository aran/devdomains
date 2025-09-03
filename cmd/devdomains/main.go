package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aran/devdomains/internal/caddy"
	"github.com/aran/devdomains/internal/dns"
	"github.com/aran/devdomains/internal/html"
	"github.com/aran/devdomains/internal/mdns"
	"github.com/aran/devdomains/internal/network"
	"github.com/aran/devdomains/internal/profile"
	"github.com/aran/devdomains/internal/version"
	"github.com/aran/devdomains/internal/wireguard"
	qrcode "github.com/skip2/go-qrcode"
	"github.com/spf13/cobra"
)

// DomainPortMapping represents a mapping from external port to internal port for a domain
type DomainPortMapping struct {
	ExternalPort int // The port Caddy listens on
	InternalPort int // The port on localhost to forward to
}

// DomainMapping represents a domain with its port mappings
type DomainMapping struct {
	Domain       string              // Domain name (e.g., dev.example.com)
	PortMappings []DomainPortMapping // Port mappings for this domain
}

// Config holds the application configuration
type Config struct {
	ServerPort     int             // Port for the HTTP server itself
	TargetHost     string          // Target host to forward requests to
	DomainMappings []DomainMapping // Domain mappings
	EnableWireGuard bool           // Enable WireGuard VPN mode
}


func main() {
	var domainMappingStrings []string

	log.SetPrefix("[devdomains] ")
	cfg := Config{
		ServerPort:  9999,
		TargetHost:  "localhost",
		// No default domain mappings, these will come from the --domain flag
	}


	rootCmd := &cobra.Command{
		Use:   "devdomains",
		Short: "DevDomains - Local development with secure HTTPS and DNS over HTTPS",
		Long: `DevDomains advertises a local service via mDNS, provides a self-signed certificate,
serves DNS over HTTPS, and configures Caddy to proxy requests to your local services.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(domainMappingStrings) == 0 {
				log.Fatalf("Error: At least one --domain mapping is required")
			}

			// Parse domain mappings from command line
			cfg.DomainMappings = []DomainMapping{}
			domainMap := make(map[string][]DomainPortMapping)

			for _, domainMapping := range domainMappingStrings {
				// Split domain from port mappings
				firstColonIndex := strings.Index(domainMapping, ":")
				if firstColonIndex == -1 {
					log.Fatalf("Invalid domain mapping format: %s. Use domain:externalPort:internalPort[,...]", domainMapping)
				}

				domain := domainMapping[:firstColonIndex]
				portMappingsStr := domainMapping[firstColonIndex+1:]

				// Split multiple port mappings by comma
				portPairSpecs := strings.Split(portMappingsStr, ",")
				for _, portPairSpec := range portPairSpecs {
					// Split each port mapping by colon
					portParts := strings.Split(portPairSpec, ":")
					if len(portParts) != 2 {
						log.Fatalf("Invalid port mapping format: %s. Use externalPort:internalPort", portPairSpec)
					}

					externalPort, err := strconv.Atoi(portParts[0])
					if err != nil {
						log.Fatalf("Invalid external port: %s", portParts[0])
					}

					internalPort, err := strconv.Atoi(portParts[1])
					if err != nil {
						log.Fatalf("Invalid internal port: %s", portParts[1])
					}

					// Add this port mapping to the domain's list
					domainMap[domain] = append(domainMap[domain], DomainPortMapping{
						ExternalPort: externalPort,
						InternalPort: internalPort,
					})

				}
			}

			// Now convert the map to our slice structure
			for domain, portMappings := range domainMap {
				cfg.DomainMappings = append(cfg.DomainMappings, DomainMapping{
					Domain:       domain,
					PortMappings: portMappings,
				})
			}
			run(cfg)
		},
	}

	rootCmd.Flags().IntVar(&cfg.ServerPort, "server-port", cfg.ServerPort, "HTTP server port")
	rootCmd.Flags().StringVar(&cfg.TargetHost, "target-host", cfg.TargetHost, "Target host to forward requests to")
	rootCmd.Flags().StringArrayVar(&domainMappingStrings, "domain", []string{},
		"Domain mappings in format domain:externalPort:internalPort[,externalPort:internalPort...] "+
			"(e.g., dev.example.com:443:8000,18080:8080). Each port mapping consists of an external port (what Caddy listens on) "+
			"and an internal port (what it forwards to).")
	rootCmd.Flags().BoolVar(&cfg.EnableWireGuard, "wireguard", false, "Enable WireGuard VPN mode for Android client support")
	
	// Add DNS subcommand for privileged DNS server
	dnsCmd := &cobra.Command{
		Use:    "dns",
		Short:  "Run DNS server only (internal use for port 53 binding)",
		Hidden: true, // Hide from help output
		Run:    runDNSServer,
	}
	
	dnsCmd.Flags().String("bind", "", "Address to bind DNS server to")
	dnsCmd.Flags().StringSlice("domains", []string{}, "Domains to resolve")
	dnsCmd.MarkFlagRequired("bind")
	dnsCmd.MarkFlagRequired("domains")
	
	rootCmd.AddCommand(dnsCmd)
	
	// Set version information for --version flag
	rootCmd.Version = version.Version

	// Add a custom template for the version command that displays full info
	rootCmd.SetVersionTemplate(version.Info())
	
	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

// runDNSServer runs just the DNS server - used as a subprocess for privileged port binding
func runDNSServer(cmd *cobra.Command, args []string) {
	bindAddr, _ := cmd.Flags().GetString("bind")
	domains, _ := cmd.Flags().GetStringSlice("domains")
	
	// Parse bind address to get IP and port
	host, portStr, err := net.SplitHostPort(bindAddr)
	if err != nil {
		log.Fatalf("Invalid bind address: %v", err)
	}
	
	port, err := strconv.Atoi(portStr)
	if err != nil {
		log.Fatalf("Invalid port: %v", err)
	}
	
	// Start DNS server using existing code
	dnsServer := dns.NewServerWithAddress(domains, host, port)
	if err := dnsServer.Start(); err != nil {
		log.Fatalf("Failed to start DNS server: %v", err)
	}
	
	log.Printf("DNS server running on %s for domains: %v", bindAddr, domains)
	
	// Block until signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan
	
	log.Println("DNS server shutting down")
	dnsServer.Stop()
}

func run(cfg Config) {
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.ServerPort),
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	profileManager := profile.NewProfileManager(cwd)

	// Get all domains for HTML and DNS handlers
	var allDomains []string
	for _, domainMapping := range cfg.DomainMappings {
		allDomains = append(allDomains, domainMapping.Domain)
	}

	// Get primary IP for display
	primaryIP := network.GetPrimaryIP()

	// Convert our domain port mappings to the HTML template format
	var htmlPortMappings []html.PortMapping
	for _, domainMapping := range cfg.DomainMappings {
		for _, portMapping := range domainMapping.PortMappings {
			htmlPortMappings = append(htmlPortMappings, html.PortMapping{
				Domain:       domainMapping.Domain,
				ExternalPort: portMapping.ExternalPort,
				InternalPort: portMapping.InternalPort,
			})
		}
	}

	http.HandleFunc("/", html.IndexHandler(cfg.ServerPort, htmlPortMappings, primaryIP, cfg.EnableWireGuard))

	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(profileManager.ProfilePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", "attachment; filename=apple_cert_trust.mobileconfig")
		http.ServeFile(w, r, profileManager.ProfilePath)
	})

	// Add endpoint for downloading the root certificate
	http.HandleFunc("/cert", func(w http.ResponseWriter, r *http.Request) {
		certPath := filepath.Join(cwd, "certs", "root-ca.crt")
		if _, err := os.Stat(certPath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-x509-ca-cert")
		w.Header().Set("Content-Disposition", "attachment; filename=devdomains-root-ca.crt")
		http.ServeFile(w, r, certPath)
	})

	// DNS-over-HTTPS handler: accessed via https://back.local/dns-query (Caddy proxies to here)
	// The iOS/macOS profile configures devices to use this endpoint for resolving the configured domains
	http.HandleFunc("/dns-query", dns.DoHHandlerMulti(allDomains))

	// WireGuard setup if enabled
	var wgServer *wireguard.Server
	var dnsProcess *exec.Cmd
	if cfg.EnableWireGuard {
		log.Println("WireGuard mode enabled - setting up VPN server...")
		
		ctx := context.Background()
		wgServer, err = wireguard.NewServer(ctx, cwd)
		if err != nil {
			log.Fatalf("Failed to create WireGuard server: %v", err)
		}
		
		// Initialize WireGuard (load/generate keys and configs)
		if err := wgServer.Initialize(); err != nil {
			log.Fatalf("Failed to initialize WireGuard: %v", err)
		}
		
		// Start WireGuard interface
		if err := wgServer.Start(); err != nil {
			log.Fatalf("Failed to start WireGuard: %v", err)
		}
		defer wgServer.Stop()
		
		// Start DNS server as privileged subprocess
		// Use os.Executable() to get the actual binary path, which works with 'go run'
		binaryPath, err := os.Executable()
		if err != nil {
			log.Fatalf("Could not determine executable path: %v", err)
		}
		
		dnsProcess = exec.Command("sudo", binaryPath, "dns",
			"--bind", fmt.Sprintf("%s:53", wgServer.GetServerIP()),
			"--domains", strings.Join(allDomains, ","))
		
		// Pipe all output so users can see DNS server logs
		dnsProcess.Stdout = os.Stdout
		dnsProcess.Stderr = os.Stderr
		dnsProcess.Stdin = os.Stdin // Allow sudo password prompt
		
		if err := dnsProcess.Start(); err != nil {
			log.Fatalf("Failed to start DNS server: %v", err)
		}
		
		// Ensure DNS process is killed on exit
		defer func() {
			if dnsProcess != nil && dnsProcess.Process != nil {
				dnsProcess.Process.Kill()
			}
		}()
		
		log.Printf("DNS server started on %s:53", wgServer.GetServerIP())
		
		// Add WireGuard config download endpoint
		http.HandleFunc("/wg-client.conf", func(w http.ResponseWriter, r *http.Request) {
			config, err := wgServer.GetClientConfig()
			if err != nil {
				http.Error(w, "Failed to get WireGuard config", http.StatusInternalServerError)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Disposition", "attachment; filename=wg-client.conf")
			w.Write([]byte(config))
		})
		
		// Add WireGuard QR code endpoint
		http.HandleFunc("/wireguard-qr.png", func(w http.ResponseWriter, r *http.Request) {
			config, err := wgServer.GetClientConfig()
			if err != nil {
				http.Error(w, "Failed to get WireGuard config", http.StatusInternalServerError)
				return
			}
			
			// Generate QR code PNG
			png, err := qrcode.Encode(config, qrcode.Medium, 512)
			if err != nil {
				http.Error(w, "Failed to generate QR code", http.StatusInternalServerError)
				return
			}
			
			w.Header().Set("Content-Type", "image/png")
			w.Write(png)
		})
		
		log.Println("WireGuard server ready - client config available at /wg-client.conf and QR code at /wireguard-qr.png")
	}

	serviceConfig := mdns.DefaultServiceConfig
	serviceConfig.Port = cfg.ServerPort

	mdnsServer, err := mdns.SetupServer(serviceConfig)
	if err != nil {
		log.Fatalf("Failed to setup mDNS server: %v", err)
	}
	defer mdnsServer.Shutdown()

	// Get hostnames for the mDNS service
	mdnsHostnames := mdns.GetServiceHostnames(serviceConfig)

	// Convert our domain mappings to the caddy format
	var caddyDomainMappings []caddy.DomainMapping
	for _, domainMapping := range cfg.DomainMappings {
		var portMappings []caddy.PortMapping
		for _, pm := range domainMapping.PortMappings {
			portMappings = append(portMappings, caddy.PortMapping{
				ExternalPort: pm.ExternalPort,
				TargetPort:   pm.InternalPort,
				TargetHost:   cfg.TargetHost,
			})
		}

		caddyDomainMappings = append(caddyDomainMappings, caddy.DomainMapping{
			Domain:       domainMapping.Domain,
			PortMappings: portMappings,
		})
	}

	caddyConfigPath := caddy.DefaultConfigPath

	// Generate Caddy config with port forwarding for all domains
	certGenerated, profileGenerated, err := caddy.GenerateConfig(mdnsHostnames, caddyDomainMappings, cfg.ServerPort, caddyConfigPath)
	if err != nil {
		log.Printf("Warning: Failed to generate Caddy configuration: %v", err)
	} else {
		absPath, err := filepath.Abs(caddyConfigPath)
		if err != nil {
			absPath = caddyConfigPath
		}

		log.Printf("Caddy configuration generated at: %s", absPath)

		if certGenerated {
			log.Printf("Self-signed TLS certificates have been generated for HTTPS")
		} else {
			log.Printf("Using existing TLS certificates for HTTPS")
		}

		if profileGenerated {
			profilePath := filepath.Join(cwd, "profiles", "apple_cert_trust.mobileconfig")
			absProfilePath, err := filepath.Abs(profilePath)
			if err != nil {
				absProfilePath = profilePath
			}
			log.Printf("Apple provisioning profile generated at: %s", absProfilePath)
		}

		log.Printf("🚀 Caddy will be started automatically as a reverse proxy")

		// Print information about accessing the target domains
		if len(cfg.DomainMappings) > 0 {
			log.Printf("🔗 After installing the profile, access your local services at:")
			for _, domainMapping := range cfg.DomainMappings {
				for _, mapping := range domainMapping.PortMappings {
					log.Printf("   https://%s:%d → %s:%d",
						domainMapping.Domain, mapping.ExternalPort, cfg.TargetHost, mapping.InternalPort)
				}
			}
		}
	}

	// Log server info  
	mdnsHost := strings.TrimSuffix(serviceConfig.Hostname, ".")

	// Start Caddy as a subprocess
	log.Printf("Starting Caddy server for HTTPS and DNS-over-HTTPS...")
	caddyCmd := exec.Command("caddy", "run", "--watch")

	// Create a pipe for Caddy's stdout and stderr
	caddyStdoutPipe, err := caddyCmd.StdoutPipe()
	if err != nil {
		log.Printf("Warning: Failed to create pipe for Caddy output: %v", err)
	} else {
		go func() {
			scanner := bufio.NewScanner(caddyStdoutPipe)
			for scanner.Scan() {
				// Use fmt because Caddy will format itself
				fmt.Printf("[Caddy] %s\n", scanner.Text())
			}
		}()
	}

	caddyStderrPipe, err := caddyCmd.StderrPipe()
	if err != nil {
		log.Printf("Warning: Failed to create pipe for Caddy error output: %v", err)
	} else {
		go func() {
			scanner := bufio.NewScanner(caddyStderrPipe)
			for scanner.Scan() {
				fmt.Printf("[Caddy] %s\n", scanner.Text())
			}
		}()
	}

	// Variable to track if Caddy is running
	var caddyRunning bool

	// Start Caddy
	if err := caddyCmd.Start(); err != nil {
		log.Printf("Warning: Failed to start Caddy: %v", err)
		log.Printf("DNS-over-HTTPS self-test will be skipped")
	} else {
		log.Printf("Caddy started successfully (PID: %d)", caddyCmd.Process.Pid)
		caddyRunning = true

		// Run DNS self-tests after servers start
		go func() {
			// Give servers a little time to start
			time.Sleep(2 * time.Second)

			testOpts := dns.SelfTestOptions{
				ServerHostname: strings.TrimSuffix(serviceConfig.Hostname, "."),
				ServerPort:     443, // Caddy serves HTTPS on port 443 by default
				RootCAPath:     filepath.Join(cwd, "certs", "root-ca.crt"),
			}

			// Test each domain
			for _, domain := range allDomains {
				testOpts.TargetDomain = domain

				// DNS-over-HTTPS tests
				if caddyRunning {
					log.Printf("Running DNS-over-HTTPS self-test for domain: %s", domain)

					// Try GET method first
					err := dns.RunSelfTest(testOpts)
					if err != nil {
						log.Printf("⚠️ DNS-over-HTTPS GET self-test for %s failed: %v", domain, err)

						// If GET failed, try POST method as a fallback
						err = dns.RunSelfTestPost(testOpts)
						if err != nil {
							log.Printf("⚠️ DNS-over-HTTPS POST self-test for %s also failed: %v", domain, err)
							log.Printf("⚠️ Note: The self-test failure doesn't prevent the server from running")
							log.Printf("⚠️ DNS resolution for %s might not work correctly until the issue is resolved", domain)
						} else {
							log.Printf("✓ DNS-over-HTTPS POST self-test for %s passed successfully", domain)
						}
					}
				} else {
					log.Printf("⚠️ Skipping DNS-over-HTTPS self-test: Caddy is not running")
				}

			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	
	go func() {
		<-stop
		log.Println("\nShutting down...")
		
		// Kill DNS subprocess if running
		if dnsProcess != nil && dnsProcess.Process != nil {
			log.Println("Stopping DNS server...")
			dnsProcess.Process.Kill()
		}
		
		// Stop WireGuard if running
		if wgServer != nil {
			log.Println("Stopping WireGuard...")
			wgServer.Stop()
		}
		
		// Stop Caddy gracefully if it's running
		if caddyCmd.Process != nil {
			log.Printf("Stopping Caddy server...")
			if err := caddyCmd.Process.Signal(os.Interrupt); err != nil {
				log.Printf("Error sending interrupt signal to Caddy: %v", err)
				// Force kill if interrupt doesn't work
				if err := caddyCmd.Process.Kill(); err != nil {
					log.Printf("Error killing Caddy process: %v", err)
				}
			}
		}
		
		// Shutdown HTTP server
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		server.Shutdown(ctx)
	}()
	
	// Start HTTP server (blocking)
	log.Printf("HTTP server starting on :%d", cfg.ServerPort)
	log.Printf("Access local server at http://%s:%d", mdnsHost, cfg.ServerPort)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server error: %v", err)
	}

	log.Println("Servers exited gracefully")
}
