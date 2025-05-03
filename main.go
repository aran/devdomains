package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/aran/mdns-caddy/pkg/caddy"
	"github.com/aran/mdns-caddy/pkg/html"
	"github.com/aran/mdns-caddy/pkg/mdns"
	"github.com/aran/mdns-caddy/pkg/profile"
)

func main() {
	port := 9999

	server := &http.Server{
		Addr: fmt.Sprintf(":%d", port),
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Fatalf("Failed to get current working directory: %v", err)
	}

	profileManager := profile.NewProfileManager(cwd)

	http.HandleFunc("/", html.IndexHandler(port))

	http.HandleFunc("/p", func(w http.ResponseWriter, r *http.Request) {
		if _, err := os.Stat(profileManager.ProfilePath); os.IsNotExist(err) {
			http.NotFound(w, r)
			return
		}

		w.Header().Set("Content-Type", "application/x-apple-aspen-config")
		w.Header().Set("Content-Disposition", "attachment; filename=apple_cert_trust.mobileconfig")
		http.ServeFile(w, r, profileManager.ProfilePath)
	})

	serviceConfig := mdns.DefaultServiceConfig
	serviceConfig.Port = port

	mdnsServer, err := mdns.SetupServer(serviceConfig)
	if err != nil {
		log.Fatalf("Failed to setup mDNS server: %v", err)
	}
	defer mdnsServer.Shutdown()

	hostnames := mdns.GetServiceHostnames(serviceConfig)
	caddyConfigPath := caddy.DefaultConfigPath
	
	certGenerated, profileGenerated, err := caddy.GenerateConfig(hostnames, port, caddyConfigPath)
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
	}

	go func() {
		log.Printf("HTTP server starting on :%d", port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("HTTP server error: %v", err)
		}
	}()

	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

	<-stop
	log.Println("Shutting down servers...")

	if err := server.Shutdown(context.Background()); err != nil {
		log.Fatalf("HTTP server shutdown error: %v", err)
	}

	log.Println("Servers exited gracefully")
}