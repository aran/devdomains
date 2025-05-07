package profile

import (
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
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

func (p *ProfileManager) GenerateProfile(rootCAPath, mdnsHostname, targetDomain string) error {
	rootCACertData, err := os.ReadFile(rootCAPath)
	if err != nil {
		return fmt.Errorf("error reading root CA certificate: %w", err)
	}

	rootCABase64 := base64.StdEncoding.EncodeToString(rootCACertData)

	// Remove trailing dot from hostnames if present
	if len(mdnsHostname) > 0 && mdnsHostname[len(mdnsHostname)-1] == '.' {
		mdnsHostname = mdnsHostname[:len(mdnsHostname)-1]
	}

	profileData := struct {
		RootCertBase64       string
		MainUUID             string
		RootCertUUID         string
		IntermediateCertUUID string
		DNSPayloadUUID       string
		MDNSHostname         string
		TargetDomain         string
		Timestamp            string
	}{
		RootCertBase64:       rootCABase64,
		MainUUID:             uuid.New().String(),
		RootCertUUID:         uuid.New().String(),
		IntermediateCertUUID: uuid.New().String(),
		DNSPayloadUUID:       uuid.New().String(),
		MDNSHostname:         mdnsHostname,
		TargetDomain:         targetDomain,
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
    <string>This profile configures your device to trust local TLS certificates and resolve {{.TargetDomain}} through your local DNS-over-HTTPS server.</string>
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
            <string>DNS Settings for {{.TargetDomain}}</string>
            <key>PayloadDescription</key>
            <string>Configures DNS over HTTPS to resolve {{.TargetDomain}} to your local machine</string>
            <key>DNSSettings</key>
            <dict>
                <key>DNSProtocol</key>
                <string>HTTPS</string>
                <key>ServerURL</key>
                <string>https://{{.MDNSHostname}}/dns-query</string>
                <key>SupplementalMatchDomains</key>
                <array>
                    <string>{{.TargetDomain}}</string>
                </array>
            </dict>
            <!-- This configuration ensures all DNS queries for the target domain are reliably handled by the local server -->
        </dict>
    </array>
</dict>
</plist>`