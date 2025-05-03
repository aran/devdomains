package cert

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"go.step.sm/crypto/keyutil"
	"go.step.sm/crypto/pemutil"
)

const (
	DefaultRootValidity = time.Hour * 24 * 365 * 10
	DefaultLeafValidity = time.Hour * 24 * 90
	DefaultKeyType      = "EC"
	DefaultCurve        = "P-256"
)

type CertPaths struct {
	RootCAPath   string
	RootKeyPath  string
	LeafCertPath string
	LeafKeyPath  string
}

type Manager struct {
	CertDir string
	Paths   CertPaths
}

func NewManager(baseDir string) *Manager {
	certDir := filepath.Join(baseDir, "certs")
	
	return &Manager{
		CertDir: certDir,
		Paths: CertPaths{
			RootCAPath:   filepath.Join(certDir, "root-ca.crt"),
			RootKeyPath:  filepath.Join(certDir, "root-ca.key"),
			LeafCertPath: filepath.Join(certDir, "leaf.crt"),
			LeafKeyPath:  filepath.Join(certDir, "leaf.key"),
		},
	}
}

func (m *Manager) EnsureCA() error {
	if err := os.MkdirAll(m.CertDir, 0700); err != nil {
		return fmt.Errorf("error creating certificate directory: %w", err)
	}

	if _, err := os.Stat(m.Paths.RootCAPath); err == nil {
		return nil
	}

	pub, priv, err := keyutil.GenerateKeyPair(DefaultKeyType, DefaultCurve, 0)
	if err != nil {
		return fmt.Errorf("error generating root key pair: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("error generating serial number: %w", err)
	}

	signer, ok := priv.(crypto.Signer)
	if !ok {
		return fmt.Errorf("private key does not implement crypto.Signer")
	}

	now := time.Now()
	rootTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: "mDNS Caddy Local Root CA",
		},
		NotBefore:             now,
		NotAfter:              now.Add(DefaultRootValidity),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, pub, signer)
	if err != nil {
		return fmt.Errorf("error generating root certificate: %w", err)
	}

	rootCert, err := x509.ParseCertificate(rootDER)
	if err != nil {
		return fmt.Errorf("error parsing root certificate: %w", err)
	}

	if err := saveCertificate(m.Paths.RootCAPath, rootCert); err != nil {
		return fmt.Errorf("error saving root certificate: %w", err)
	}

	_, err = pemutil.Serialize(priv, pemutil.ToFile(m.Paths.RootKeyPath, 0600))
	if err != nil {
		return fmt.Errorf("error saving root key: %w", err)
	}

	return nil
}

func (m *Manager) EnsureCertificate(hostnames []string) error {
	if len(hostnames) == 0 {
		return fmt.Errorf("no hostnames provided")
	}

	if _, err := os.Stat(m.Paths.LeafCertPath); err == nil {
		return nil
	}

	return m.GenerateCertificate(hostnames)
}

func (m *Manager) GenerateCertificate(hostnames []string) error {
	if len(hostnames) == 0 {
		return fmt.Errorf("no hostnames provided")
	}

	rootCertBytes, err := os.ReadFile(m.Paths.RootCAPath)
	if err != nil {
		return fmt.Errorf("error reading root certificate: %w", err)
	}

	block, _ := pem.Decode(rootCertBytes)
	if block == nil {
		return fmt.Errorf("error decoding root certificate PEM")
	}

	rootCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("error parsing root certificate: %w", err)
	}

	rootKeyBytes, err := os.ReadFile(m.Paths.RootKeyPath)
	if err != nil {
		return fmt.Errorf("error reading root key: %w", err)
	}

	rootKey, err := pemutil.ParseKey(rootKeyBytes)
	if err != nil {
		return fmt.Errorf("error parsing root key: %w", err)
	}

	signer, ok := rootKey.(crypto.Signer)
	if !ok {
		return fmt.Errorf("root key does not implement crypto.Signer")
	}

	pub, priv, err := keyutil.GenerateKeyPair(DefaultKeyType, DefaultCurve, 0)
	if err != nil {
		return fmt.Errorf("error generating leaf key pair: %w", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("error generating serial number: %w", err)
	}

	now := time.Now()
	leafTemplate := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostnames[0],
		},
		NotBefore:             now,
		NotAfter:              now.Add(DefaultLeafValidity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              hostnames,
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, rootCert, pub, signer)
	if err != nil {
		return fmt.Errorf("error generating leaf certificate: %w", err)
	}

	leafCert, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return fmt.Errorf("error parsing leaf certificate: %w", err)
	}

	if err := saveCertificate(m.Paths.LeafCertPath, leafCert); err != nil {
		return fmt.Errorf("error saving leaf certificate: %w", err)
	}

	_, err = pemutil.Serialize(priv, pemutil.ToFile(m.Paths.LeafKeyPath, 0600))
	if err != nil {
		return fmt.Errorf("error saving leaf key: %w", err)
	}

	return nil
}

func saveCertificate(path string, cert *x509.Certificate) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return fmt.Errorf("error creating directory %s: %w", dir, err)
	}

	certPEM := &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	}

	certBytes := pem.EncodeToMemory(certPEM)
	if certBytes == nil {
		return fmt.Errorf("failed to encode certificate to PEM")
	}

	return os.WriteFile(path, certBytes, 0600)
}