package profile

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
)

const (
	DefaultProfileDir = "profiles"
	ProfileFilename   = "apple_cert_trust.mobileconfig"
)

type ProfileManager struct {
	ProfileDir  string
	ProfilePath string
}

func NewProfileManager(baseDir string) *ProfileManager {
	profileDir := filepath.Join(baseDir, DefaultProfileDir)

	return &ProfileManager{
		ProfileDir:  profileDir,
		ProfilePath: filepath.Join(profileDir, ProfileFilename),
	}
}

func (p *ProfileManager) EnsureProfileDir() error {
	return os.MkdirAll(p.ProfileDir, 0755)
}

// GenerateProfile generates a profile for multiple domains
func (p *ProfileManager) GenerateProfile(rootCAPath string, mdnsHostname string, domains []string) error {
	if len(domains) == 0 {
		return fmt.Errorf("no domains provided for profile generation")
	}

	rootCACertData, err := os.ReadFile(rootCAPath)
	if err != nil {
		return fmt.Errorf("error reading root CA certificate: %w", err)
	}

	rootCABase64 := base64.StdEncoding.EncodeToString(rootCACertData)

	// Remove trailing dot from hostnames if present
	if len(mdnsHostname) > 0 && mdnsHostname[len(mdnsHostname)-1] == '.' {
		mdnsHostname = mdnsHostname[:len(mdnsHostname)-1]
	}

	// Create a description with the domains
	var domainDesc string
	if len(domains) == 1 {
		domainDesc = domains[0]
	} else if len(domains) == 2 {
		domainDesc = domains[0] + " and " + domains[1]
	} else {
		domainDesc = strings.Join(domains[:len(domains)-1], ", ") + ", and " + domains[len(domains)-1]
	}

	profileData := struct {
		RootCertBase64       string
		MainUUID             string
		RootCertUUID         string
		IntermediateCertUUID string
		DNSPayloadUUID       string
		MDNSHostname         string
		Domains              []string
		DomainDesc           string
		Timestamp            string
	}{
		RootCertBase64:       rootCABase64,
		MainUUID:             uuid.New().String(),
		RootCertUUID:         uuid.New().String(),
		IntermediateCertUUID: uuid.New().String(),
		DNSPayloadUUID:       uuid.New().String(),
		MDNSHostname:         mdnsHostname,
		Domains:              domains,
		DomainDesc:           domainDesc,
		Timestamp:            time.Now().Format(time.RFC3339),
	}

	tmpl, err := template.New("profile").Parse(profileTemplate)
	if err != nil {
		return fmt.Errorf("error parsing profile template: %w", err)
	}

	if err := p.EnsureProfileDir(); err != nil {
		return fmt.Errorf("error creating profile directory: %w", err)
	}

	file, err := os.Create(p.ProfilePath)
	if err != nil {
		return fmt.Errorf("error creating profile file: %w", err)
	}
	defer file.Close()

	if err := tmpl.Execute(file, profileData); err != nil {
		return fmt.Errorf("error executing profile template: %w", err)
	}

	return nil
}

func (p *ProfileManager) ProfileExists() bool {
	_, err := os.Stat(p.ProfilePath)
	return err == nil
}

const profileTemplate = `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <!-- Top-level profile properties -->
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
    <key>PayloadIdentifier</key>
    <string>com.mdns-caddy.configuration</string>
    <key>PayloadUUID</key>
    <string>{{.MainUUID}}</string>
    <key>PayloadDisplayName</key>
    <string>mDNS Caddy Configuration</string>
    <key>PayloadDescription</key>
    <string>This profile configures your device to trust local TLS certificates and resolve {{.DomainDesc}} through your local DNS-over-HTTPS server.</string>
    <key>PayloadContent</key>
    <array>
        <!-- Root Certificate Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.mdns-caddy.tls.rootcert</string>
            <key>PayloadUUID</key>
            <string>{{.RootCertUUID}}</string>
            <key>PayloadDisplayName</key>
            <string>mDNS Caddy Root Certificate</string>
            <key>PayloadDescription</key>
            <string>Adds the mDNS Caddy CA root certificate</string>
            <key>PayloadContent</key>
            <data>
                {{.RootCertBase64}}
            </data>
        </dict>

        <!-- DNS Settings Payload -->
        <dict>
            <key>PayloadType</key>
            <string>com.apple.dnsSettings.managed</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
            <key>PayloadIdentifier</key>
            <string>com.mdns-caddy.dns</string>
            <key>PayloadUUID</key>
            <string>{{.DNSPayloadUUID}}</string>
            <key>PayloadDisplayName</key>
            <string>DNS Settings for Local Development</string>
            <key>PayloadDescription</key>
            <string>Configures DNS over HTTPS to resolve domains to your local machine</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://{{.MDNSHostname}}/dns-query</string>
                <key>SupplementalMatchDomains</key>
                <array>
                    {{range .Domains}}
                    <string>{{.}}</string>
                    {{end}}
                </array>
            </dict>
            <!-- This configuration ensures all DNS queries for the domains are reliably handled by the local server -->
        </dict>
    </array>
</dict>
</plist>`