# DevDomains

DevDomains is a local development tool that creates secure HTTPS endpoints for your local services, making them accessible via custom domain names. It solves common challenges in local web development by:

- Generating self-signed TLS certificates for your development domains
- Providing local DNS resolution via DNS-over-HTTPS (DoH)
- Setting up a reverse proxy to route requests to the correct local ports
- Creating mobile configuration profiles for iOS/macOS to enable cross-device testing
- Using mDNS for easy discovery and bootstrap of the configuration service

## Installation

### Using Go Install

```bash
go install github.com/aran/devdomains/cmd/devdomains@latest
```

### From Binary Releases

Download the latest binary for your platform from the [Releases page](https://github.com/aran/devdomains/releases).

### Build from Source

```bash
git clone https://github.com/aran/devdomains.git
cd devdomains
go build ./cmd/devdomains
```

### Dependencies

DevDomains requires [Caddy](https://caddyserver.com/docs/install) to be installed on your system.

## Why Use DevDomains?

DevDomains solves several common challenges in development workflows:

- **Mobile App Testing**: Test universal links, authentication flows, and redirects on real devices
- **HTTPS Requirements**: Use modern web APIs that require secure contexts without browser warnings
- **Cross-Device Development**: Easily test on phones, tablets, and other devices on your local network
- **Domain-Specific Features**: Test functionality that depends on specific domain names
- **Local Environment Simulation**: Create a development environment that closely mirrors production

## Real-World Use Case

The authors of DevDomains created this tool specifically to test OAuth flows with universal links on iOS. 

When developing iOS apps with OAuth authentication, testing universal links and ASWebAuthenticationSession can be challenging. These mechanisms require proper domain configuration, valid HTTPS certificates, and specific apple-app-site-association files. DevDomains streamlines this process by providing the necessary infrastructure to test these flows on physical devices without deploying to staging environments.

## Developed with Claude

This project was largely written by Claude Code, including this README. The initial concept and requirements were provided by humans, but Claude did most of the implementation work, from code architecture to documentation.

## Usage Examples

### Basic Usage

Map development domains to different local ports:

```bash
devdomains --domain dev.example.com:443:8000 --domain api.example.com:443:3000
```

This will:
- Map `https://dev.example.com` to `localhost:8000`
- Map `https://api.example.com` to `localhost:3000`

### Multiple Port Mappings

You can map multiple ports for a single domain:

```bash
devdomains --domain dev.example.com:443:8000,8080:3000
```

This will:
- Map `https://dev.example.com` (port 443) to `localhost:8000`
- Map `https://dev.example.com:8080` to `localhost:3000`

### Custom Server Port

Change the configuration server port (default is 9999):

```bash
devdomains --server-port 8888 --domain dev.example.com:443:8000
```

## Setup Instructions

### iOS Setup

1. Remove existing devdomains configuration profiles from your phone/computer if this isn't the first time. Settings > General > VPN & Device Management > the profile > remove. In this folder, manually remove old profiles/certs files if you want to refresh them, for example, if debugging issues. e.g. `rm profiles/*; rm certs/*`

2. Run the command, e.g. `go run ./cmd/devdomains/main.go --domain dev.example.com:18888:8888,443:8000 --domain devaccounts.example.com:443:4433`

3. Visit http://back.local:9999 in Safari on your phone. NOT https. NOT Chrome.

4. Download the configuration profile with the big button. Hit "Allow". Hit "Close". Go to Settings. Expect to see a "Profile Downloaded" entry on the root screen, above Airplane Mode. Tap "Install" in top right corner. Enter passcode. Read the warning, Tap Install.

5. Go to Settings > General > About > Certificate Trust Settings. Enable Full Trust for the new, DevDomains Local Root CA.

6. Fully uninstall your dev iOS app (if testing universal links). Universal links check for your apple-app-site-association file on app installation. If it's not working at app installation time, universal links and ASWebAuthenticationSessions will fail. Failure symptoms include ASWebAuthenticationSession immediately closing reporting a user cancellation, or failing to close when redirected to one of your app URLs.

7. Sanity test your apple-app-site-association file (if applicable). e.g. on your laptop, `curl --insecure --resolve dev.example.com:443:127.0.0.1 https://dev.example.com/.well-known/apple-app-site-association`.

8. Install and run your app. Check your logs to make sure the expected DNS queries and apple-app-site-association queries are being performed and succeeding.

### Android Setup

Android devices can install the root certificate to trust HTTPS connections to your development domains.

1. Run DevDomains with your domain configuration:
   ```bash
   devdomains --domain dev.example.com:443:8000 --domain api.example.com:443:3000
   ```
   Note your computer's IP address (shown in the logs or on the web interface)

2. **Install the Root Certificate**:
   - Visit `http://YOUR_COMPUTER_IP:9999` in your Android browser
   - Download the Root CA Certificate
   - Go to Settings → Security → Encryption & credentials
   - Tap "Install a certificate" → "CA certificate"
   - Select the downloaded certificate file
   - Name it something like "DevDomains Local CA"

3. **Important Notes**:
   - This enables HTTPS connections to your development domains
   - DNS resolution requires additional setup in your app or using a debugging proxy
   - Android's Private DNS feature cannot be used for local development as it requires a public hostname with valid certificates
   - Consider using your app's network configuration or tools like Charles Proxy for DNS override