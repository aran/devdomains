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

type config struct {
	serverPort    int                 // Port for the HTTP server itself
	targetDomain  string              // Domain to forward to local services
	portMappings  []caddy.PortMapping // Port mappings (external:internal)
}

func main() {
	var portMappingStrings []string
	
	cfg := config{
		serverPort: 9999,
		// Default to forward port 18888 to 8888
		portMappings: []caddy.PortMapping{{ExternalPort: 18888, InternalPort: 8888}},
	}

	rootCmd := &cobra.Command{
		Use:   "mdns-caddy",
		Short: "mDNS Caddy - Local development with secure HTTPS and DNS over HTTPS",
		Long: `mDNS Caddy advertises a local service via mDNS, provides a self-signed certificate,
serves DNS over HTTPS, and configures Caddy to proxy requests to your local services.`,
		Run: func(cmd *cobra.Command, args []string) {
			if cfg.targetDomain == "" {
				log.Fatalf("Error: --target-domain is required")
				return
			}
			
			// Parse port mappings from command line
			cfg.portMappings = []caddy.PortMapping{}
			for _, mapping := range portMappingStrings {
				parts := strings.Split(mapping, ":")
				if len(parts) != 2 {
					log.Fatalf("Invalid port mapping format: %s. Use externalPort:internalPort", mapping)
					return
				}
				
				externalPort, err := strconv.Atoi(parts[0])
				if err != nil {
					log.Fatalf("Invalid external port: %s", parts[0])
					return
				}
				
				internalPort, err := strconv.Atoi(parts[1])
				if err != nil {
					log.Fatalf("Invalid internal port: %s", parts[1])
					return
				}
				
				cfg.portMappings = append(cfg.portMappings, caddy.PortMapping{
					ExternalPort: externalPort,
					InternalPort: internalPort,
				})
			}
			
			// If no port mappings were specified on the command line, use the default
			if len(cfg.portMappings) == 0 {
				cfg.portMappings = []caddy.PortMapping{{ExternalPort: 18888, InternalPort: 8888}}
			}

			run(cfg)
		},
	}

	rootCmd.Flags().IntVar(&cfg.serverPort, "server-port", cfg.serverPort, "HTTP server port")
	rootCmd.Flags().StringVar(&cfg.targetDomain, "target-domain", "", "Target domain to proxy (required)")
	rootCmd.Flags().StringSliceVar(&portMappingStrings, "port-mapping", []string{"18888:8888"}, 
		"Port mappings in format externalPort:internalPort (e.g., 18888:8888). Caddy will listen on the external port and forward to the internal port. Multiple mappings can be comma-separated.")
	rootCmd.MarkFlagRequired("target-domain")

	if err := rootCmd.Execute(); err != nil {
		log.Fatalf("Error executing command: %v", err)
	}
}

func run(cfg config) {
	server := &http.Server{
		Addr: fmt.Sprintf(":%d", cfg.serverPort),
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	profileManager := profile.NewProfileManager(cwd)

	// Convert our internal port mappings to the HTML template format
	var htmlPortMappings []html.PortMapping
	for _, mapping := range cfg.portMappings {
		htmlPortMappings = append(htmlPortMappings, html.PortMapping{
			ExternalPort: mapping.ExternalPort,
			InternalPort: mapping.InternalPort,
		})
	}

	http.HandleFunc("/", html.IndexHandler(cfg.serverPort, cfg.targetDomain, htmlPortMappings))

	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(profileManager.ProfilePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", "attachment; filename=apple_cert_trust.mobileconfig")
		http.ServeFile(w, r, profileManager.ProfilePath)
	})

	// Set up DNS-over-HTTPS handler
	http.HandleFunc("/dns-query", dns.DoHHandler(cfg.targetDomain))

	serviceConfig := mdns.DefaultServiceConfig
	serviceConfig.Port = cfg.serverPort

	mdnsServer, err := mdns.SetupServer(serviceConfig)
	if err != nil {
		log.Fatalf("Failed to setup mDNS server: %v", err)
	}
	defer mdnsServer.Shutdown()

	// Get hostnames for both the mDNS service and the target domain
	mdnsHostnames := mdns.GetServiceHostnames(serviceConfig)
	allHostnames := append(mdnsHostnames, cfg.targetDomain)

	caddyConfigPath := caddy.DefaultConfigPath
	
	// Generate Caddy config with port forwarding for the target domain
	certGenerated, profileGenerated, err := caddy.GenerateConfig(mdnsHostnames, allHostnames, cfg.serverPort, cfg.portMappings, caddyConfigPath)
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
		
		// Print information about accessing the target domain
		if len(cfg.portMappings) > 0 {
			log.Printf("🔗 After installing the profile, access your local services at:")
			for _, mapping := range cfg.portMappings {
				log.Printf("   https://%s:%d → localhost:%d", 
					cfg.targetDomain, mapping.ExternalPort, mapping.InternalPort)
			}
		}
	}

	go func() {
		mdnsHost := strings.TrimSuffix(serviceConfig.Hostname, ".")
		log.Printf("HTTP server starting on :%d", cfg.serverPort)
		log.Printf("Access local server at http://%s:%d", mdnsHost, cfg.serverPort)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()
	
	// Start Caddy as a subprocess
	log.Printf("Starting Caddy server for HTTPS and DNS-over-HTTPS...")
	caddyCmd := exec.Command("caddy", "run")
	
	// Create a pipe for Caddy's stdout and stderr
	caddyStdoutPipe, err := caddyCmd.StdoutPipe()
	if err != nil {
		log.Printf("Warning: Failed to create pipe for Caddy output: %v", err)
	} else {
		go func() {
			scanner := bufio.NewScanner(caddyStdoutPipe)
			for scanner.Scan() {
				log.Printf("[Caddy] %s", scanner.Text())
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
				log.Printf("[Caddy] %s", scanner.Text())
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
		
		// Run the DNS-over-HTTPS self-test after Caddy starts
		go func() {
			// Give Caddy a little time to start
			time.Sleep(2 * time.Second)
			
			if !caddyRunning {
				log.Printf("⚠️ Skipping DNS-over-HTTPS self-test: Caddy is not running")
				return
			}
			
			testOpts := dns.SelfTestOptions{
				TargetDomain:   cfg.targetDomain,
				ServerHostname: strings.TrimSuffix(serviceConfig.Hostname, "."), 
				ServerPort:     443, // Caddy serves HTTPS on port 443 by default
				RootCAPath:     filepath.Join(cwd, "certs", "root-ca.crt"),
			}
			
			// Try GET method first
			err := dns.RunSelfTest(testOpts)
			if err != nil {
				log.Printf("⚠️ DNS-over-HTTPS GET self-test failed: %v", err)
				
				// If GET failed, try POST method as a fallback
				err = dns.RunSelfTestPost(testOpts)
				if err != nil {
					log.Printf("⚠️ DNS-over-HTTPS POST self-test also failed: %v", err)
					log.Printf("⚠️ Note: The self-test failure doesn't prevent the server from running")
					log.Printf("⚠️ DNS resolution might not work correctly until the issue is resolved")
				}
			} else {
				log.Printf("✓ DNS-over-HTTPS self-test passed successfully")
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