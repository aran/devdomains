package html

import (
	"bytes"
	"html/template"
	"net/http"
)

// TemplateData defines the data passed to HTML templates
type TemplateData struct {
	Port        int
	HostAddress string
}

// IndexHandler returns an http.HandlerFunc that serves the index page with template data
func IndexHandler(port int) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Get host from request or use localhost if not available
		host := r.Host
		if host == "" {
			host = "localhost"
		}

		data := TemplateData{
			Port:        port,
			HostAddress: host,
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

// indexTemplate is the HTML template for the index page
const indexTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>mDNS Caddy</title>
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
    </style>
</head>
<body>
    <h1>mDNS Caddy Server</h1>
    <div class="info">
        <p>This server is running on port <code>{{.Port}}</code> and provides support for mDNS discovery and TLS certificate provisioning.</p>
        <p>If you need to install the TLS certificate on your device, you can access the Apple provisioning profile.</p>
        <a href="http://{{.HostAddress}}:{{.Port}}/p" class="link">Download TLS Certificate Profile</a>
    </div>
</body>
</html>`