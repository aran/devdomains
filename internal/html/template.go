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
	Port         int
	HostAddress  string
	PortMappings []PortMapping
}

func IndexHandler(port int, portMappings []PortMapping) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if host == "" {
			host = "localhost"
		}

		data := TemplateData{
			Port:         port,
			HostAddress:  host,
			PortMappings: portMappings,
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
    </style>
</head>
<body>
    <h1>Dev Domains Server</h1>

    <div class="info">
        <p>This server is running on port <code>{{.Port}}</code> and provides the following features:</p>
        <ul>
            <li>mDNS discovery for local services</li>
            <li>Self-signed TLS certificates for secure connections</li>
            <li>DNS over HTTPS for targeted domain resolution</li>
            <li>Caddy reverse proxy configuration</li>
        </ul>
        <a href="/p" class="link">Download Configuration Profile</a>
    </div>

    <h2>Root Certificate</h2>
    <div class="feature">
        <p>For manual certificate installation or debugging purposes, you can download the root CA certificate directly:</p>
        <a href="/cert" class="link">Download Root CA Certificate</a>
        <p><small>Note: The configuration profile above includes this certificate and is the recommended installation method for iOS/macOS devices.</small></p>
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
        <h3>DNS over HTTPS</h3>
        <p>This server provides a DNS over HTTPS endpoint at:</p>
        <code>https://{{.HostAddress}}/dns-query</code>
        <p>The configuration profile will automatically use this for domain resolution.</p>
    </div>
</body>
</html>`
