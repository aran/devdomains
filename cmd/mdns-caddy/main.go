package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aran/mdns-caddy/internal/caddy"
	"github.com/aran/mdns-caddy/internal/dns"
	"github.com/aran/mdns-caddy/internal/html"
	"github.com/aran/mdns-caddy/internal/mdns"
	"github.com/aran/mdns-caddy/internal/profile"
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
	DomainMappings []DomainMapping // Domain mappings
}

func main() {
	var domainMappingStrings []string

	log.SetPrefix("[mdns-caddy] ")
	cfg := Config{
		ServerPort: 9999,
		// No default domain mappings, these will come from the --domain flag
	}

	rootCmd := &cobra.Command{
		Use:   "mdns-caddy",
		Short: "mDNS Caddy - Local development with secure HTTPS and DNS over HTTPS",
		Long: `mDNS Caddy advertises a local service via mDNS, provides a self-signed certificate,
serves DNS over HTTPS, and configures Caddy to proxy requests to your local services.`,
		Run: func(cmd *cobra.Command, args []string) {
			if len(domainMappingStrings) == 0 {
				log.Fatalf("Error: At least one --domain mapping is required")
				return
			}

			// Parse domain mappings from command line
			cfg.DomainMappings = []DomainMapping{}
			domainMap := make(map[string][]DomainPortMapping)

			for _, domainMapping := range domainMappingStrings {
				// Split domain from port mappings
				firstColonIndex := strings.Index(domainMapping, ":")
				if firstColonIndex == -1 {
					log.Fatalf("Invalid domain mapping format: %s. Use domain:externalPort:internalPort[,...]", domainMapping)
					return
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
						return
					}

					externalPort, err := strconv.Atoi(portParts[0])
					if err != nil {
						log.Fatalf("Invalid external port: %s", portParts[0])
						return
					}

					internalPort, err := strconv.Atoi(portParts[1])
					if err != nil {
						log.Fatalf("Invalid internal port: %s", portParts[1])
						return
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
	rootCmd.Flags().StringArrayVar(&domainMappingStrings, "domain", []string{},
		"Domain mappings in format domain:externalPort:internalPort[,externalPort:internalPort...] "+
			"(e.g., dev.example.com:443:8000,18080:8080). Each port mapping consists of an external port (what Caddy listens on) "+
			"and an internal port (what it forwards to on localhost).")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
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

	// The first domain will host the DNS server (consistent with your instruction)
	var dnsDomain string
	if len(allDomains) > 0 {
		dnsDomain = allDomains[0]
	}

	http.HandleFunc("/", html.IndexHandler(cfg.ServerPort, dnsDomain, htmlPortMappings))

	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(profileManager.ProfilePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", "attachment; filename=apple_cert_trust.mobileconfig")
		http.ServeFile(w, r, profileManager.ProfilePath)
	})

	// Set up DNS-over-HTTPS handler for all domains
	http.HandleFunc("/dns-query", dns.DoHHandlerMulti(allDomains))

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
				InternalPort: pm.InternalPort,
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

		log.Printf("🚀 To use Caddy as a reverse proxy, run: caddy run")

		// Print information about accessing the target domains
		if len(cfg.DomainMappings) > 0 {
			log.Printf("🔗 After installing the profile, access your local services at:")
			for _, domainMapping := range cfg.DomainMappings {
				for _, mapping := range domainMapping.PortMappings {
					log.Printf("   https://%s:%d → localhost:%d",
						domainMapping.Domain, mapping.ExternalPort, mapping.InternalPort)
				}
			}
		}
	}

	go func() {
		mdnsHost := strings.TrimSuffix(serviceConfig.Hostname, ".")
		log.Printf("HTTP server starting on :%d", cfg.ServerPort)
		log.Printf("Access local server at http://%s:%d", mdnsHost, cfg.ServerPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

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
				fmt.Printf("[Caddy] %s", scanner.Text())
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
				fmt.Printf("[Caddy] %s", scanner.Text())
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

		// Run DNS-over-HTTPS self-tests after Caddy starts
		go func() {
			// Give Caddy a little time to start
			time.Sleep(2 * time.Second)

			if !caddyRunning {
				log.Printf("⚠️ Skipping DNS-over-HTTPS self-test: Caddy is not running")
				return
			}

			// Run a DNS-over-HTTPS self-test for each domain
			for _, domain := range allDomains {
				testOpts := dns.SelfTestOptions{
					TargetDomain:   domain,
					ServerHostname: strings.TrimSuffix(serviceConfig.Hostname, "."),
					ServerPort:     443, // Caddy serves HTTPS on port 443 by default
					RootCAPath:     filepath.Join(cwd, "certs", "root-ca.crt"),
				}

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
			}
		}()
	}

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop

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
	log.Println("Shutting down servers...")

	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatalf("HTTP server shutdown error: %v", err)
	}

	log.Println("Servers exited gracefully")
}
