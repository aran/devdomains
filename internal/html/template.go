package html

import (
	"bytes"
	"html/template"
	"net/http"
)

type PortMapping struct {
	Domain       string
	ExternalPort int
	InternalPort int
}

type TemplateData struct {
	Port            int
	HostAddress     string
	LocalIP         string
	PortMappings    []PortMapping
	WireGuardEnabled bool
}

func IndexHandler(port int, portMappings []PortMapping, localIP string, wireGuardEnabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			host = "localhost"
		}

		data := TemplateData{
			Port:             port,
			HostAddress:      host,
			LocalIP:          localIP,
			PortMappings:     portMappings,
			WireGuardEnabled: wireGuardEnabled,
		}

		tmpl, err := template.New("index").Parse(indexTemplate)
		if err != nil {
			http.Error(w, "Template error", http.StatusInternalServerError)
			return
		}

		buf := new(bytes.Buffer)
		if err := tmpl.Execute(buf, data); err != nil {
			http.Error(w, "Template execution error", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(buf.Bytes())
	}
}

const indexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Dev Domains</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 800px;
            margin: 0 auto;
            padding: 20px;
        }
        h1 {
            color: #2c3e50;
            border-bottom: 1px solid #eee;
            padding-bottom: 10px;
        }
        h2 {
            color: #2c3e50;
            margin-top: 30px;
        }
        .info {
            background-color: #f8f9fa;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 20px 0;
        }
        .link {
            display: inline-block;
            margin-top: 15px;
            background-color: #3498db;
            color: white;
            padding: 10px 15px;
            text-decoration: none;
            border-radius: 4px;
        }
        .link:hover {
            background-color: #2980b9;
        }
        code {
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
            font-family: monospace;
        }
        .feature {
            margin-bottom: 20px;
        }
        .platform-section {
            border: 1px solid #e0e0e0;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .platform-section h3 {
            margin-top: 0;
            color: #2c3e50;
        }
        .command {
            background-color: #2c3e50;
            color: #fff;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            margin: 10px 0;
            overflow-x: auto;
            position: relative;
        }
        .copy-btn {
            position: absolute;
            top: 5px;
            right: 5px;
            background: #3498db;
            color: white;
            border: none;
            padding: 5px 10px;
            border-radius: 3px;
            cursor: pointer;
            font-size: 12px;
        }
        .copy-btn:hover {
            background: #2980b9;
        }
        .copy-btn.copied {
            background: #27ae60;
        }
    </style>
</head>
<body>
    <h1>Dev Domains Server</h1>

    <div class="info">
        <p>This server is running on port <code>{{.Port}}</code> and provides the following features:</p>
        <ul>
            <li>mDNS discovery for local services (iOS/macOS compatible)</li>
            <li>Self-signed TLS certificates for secure HTTPS connections</li>
            <li>DNS-over-HTTPS for domain resolution</li>
            <li>Caddy reverse proxy for port forwarding</li>
        </ul>
        <a href="/p" class="link">Download Configuration Profile (iOS/macOS)</a>
    </div>

    <h2>Platform Setup Instructions</h2>
    
    <div class="platform-section">
        <h3>📱 iOS/macOS Setup</h3>
        <p>For Apple devices, use the configuration profile which includes certificate and DNS settings:</p>
        <ol>
            <li>Open Safari (not Chrome) and visit: <code>http://{{.HostAddress}}</code></li>
            <li>Tap "Download Configuration Profile" button to download the profile</li>
            <li>Open Settings app → Look for "Profile Downloaded" near the top</li>
            <li>Tap "Install" and enter your passcode when prompted</li>
            <li>After installation, go to Settings → General → About → Certificate Trust Settings</li>
            <li>Enable full trust for "DevDomains Local Root CA"</li>
        </ol>
        <p><small>The profile automatically configures DNS-over-HTTPS for your domains.</small></p>
    </div>

    <div class="platform-section">
        <h3>🤖 Android Setup</h3>
        <p>For Android devices, you need to install the root certificate to trust HTTPS connections:</p>
        
        <h4>Install Root Certificate</h4>
        <ol>
            <li>Visit <code>http://{{if .LocalIP}}{{.LocalIP}}{{else}}YOUR_COMPUTER_IP{{end}}:{{.Port}}</code> on your Android device</li>
            <li>Download the <a href="/cert">Root CA Certificate</a></li>
            <li>Go to Settings → Security → Encryption & credentials</li>
            <li>Tap "Install a certificate" → "CA certificate"</li>
            <li>Select the downloaded certificate file</li>
            <li>Give it a name like "DevDomains Local CA"</li>
        </ol>
        
        {{if .WireGuardEnabled}}
        <h4>WireGuard VPN for DNS Support</h4>
        <p><strong>WireGuard VPN mode is enabled!</strong> Connect via VPN for automatic DNS resolution.</p>
        
        <p>Quick Setup:</p>
        <ol>
            <li>Install the WireGuard app from Google Play Store</li>
            <li>Open WireGuard and tap the + button</li>
            <li>Select "Scan from QR code" and scan this:</li>
        </ol>
        
        <div style="text-align: center; margin: 20px 0;">
            <img src="/wireguard-qr.png" alt="WireGuard Configuration" style="max-width: 300px; border: 1px solid #ddd; padding: 10px; background: white;">
        </div>
        
        <p>Or <a href="/wg-client.conf">download the config file</a> and import it manually.</p>
        {{else}}
        <h4>Note about DNS</h4>
        <p>Without WireGuard, DNS resolution requires configuring your app or using a local proxy. For full DNS support, run DevDomains with <code>--wireguard</code> flag.</p>
        {{end}}
        
        {{if .LocalIP}}<p><small>Your computer's IP appears to be: <code>{{.LocalIP}}</code></small></p>{{end}}
    </div>

    <h2>How it Works</h2>

    <div class="feature">
        <h3>1. Install the Configuration Profile</h3>
        <p>Download and install the configuration profile on your iOS or macOS device. This profile will:</p>
        <ul>
            <li>Install the TLS certificate for secure connections</li>
            <li>Configure DNS over HTTPS to resolve configured domains to this machine</li>
            <li>Only affect DNS resolution for the domains you've configured and their subdomains</li>
        </ul>
    </div>

    <div class="feature">
        <h3>2. Access Your Local Services</h3>
        <p>After installing the profile, you can access your local services at:</p>
        <ul>
            {{ range .PortMappings }}
            <li><code>https://{{.Domain}}:{{.ExternalPort}}</code> - Forwards to <code>localhost:{{.InternalPort}}</code></li>
            {{ end }}
        </ul>
    </div>

    <div class="feature">
        <h3>DNS Services</h3>
        <p><strong>DNS-over-HTTPS:</strong> <code>https://{{.HostAddress}}/dns-query</code></p>
        <p>This endpoint resolves your configured domains to this machine.</p>
    </div>

    <script>
    function copyCommand(elementId) {
        const element = document.getElementById(elementId);
        const textElement = element.querySelector('span');
        const button = element.querySelector('.copy-btn');
        
        // Get text content, preserving line breaks
        const text = textElement ? (textElement.innerText || textElement.textContent) : '';
        
        // Function to show success feedback
        function showCopied() {
            const originalText = button.textContent;
            button.textContent = 'Copied!';
            button.classList.add('copied');
            
            setTimeout(() => {
                button.textContent = originalText;
                button.classList.remove('copied');
            }, 2000);
        }
        
        // Try modern clipboard API first (requires HTTPS or localhost)
        if (navigator.clipboard && window.isSecureContext) {
            navigator.clipboard.writeText(text).then(() => {
                showCopied();
            }).catch(err => {
                console.error('Clipboard API failed, using fallback: ', err);
                fallbackCopy();
            });
        } else {
            // Use fallback for HTTP or older browsers
            fallbackCopy();
        }
        
        function fallbackCopy() {
            const textarea = document.createElement('textarea');
            textarea.value = text;
            textarea.style.position = 'fixed';
            textarea.style.top = '0';
            textarea.style.left = '0';
            textarea.style.width = '2em';
            textarea.style.height = '2em';
            textarea.style.padding = '0';
            textarea.style.border = 'none';
            textarea.style.outline = 'none';
            textarea.style.boxShadow = 'none';
            textarea.style.background = 'transparent';
            document.body.appendChild(textarea);
            textarea.focus();
            textarea.select();
            
            try {
                const successful = document.execCommand('copy');
                if (successful) {
                    showCopied();
                } else {
                    console.error('Fallback copy failed');
                }
            } catch (err) {
                console.error('Fallback copy error: ', err);
            }
            
            document.body.removeChild(textarea);
        }
    }
    </script>
</body>
</html>`
