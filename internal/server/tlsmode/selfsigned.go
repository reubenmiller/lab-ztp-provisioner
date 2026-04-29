package tlsmode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

// SelfSignedConfig controls generation and caching of a self-signed
// cert. The defaults (~1 year validity, P-256, every-loopback +
// hostname SAN) are tuned for laptop / single-VM use; the production
// answer remains a real CA via Caddy or autocert.
type SelfSignedConfig struct {
	// CacheDir is where the generated cert + key are persisted so
	// restarts reuse them. Created with mode 0700 if missing.
	CacheDir string

	// Hostnames are added as DNS SANs (in addition to "localhost").
	// Empty falls back to os.Hostname().
	Hostnames []string

	// IPSANs are extra IPs. 127.0.0.1 and ::1 are always added.
	IPSANs []net.IP

	// Validity is how long the generated cert is valid. Zero defaults
	// to one year.
	Validity time.Duration
}

// LoadOrGenerate returns a *tls.Certificate, reading from the cache if
// the cached cert is still valid for at least 14 days, otherwise
// generating a fresh cert and caching it.
func LoadOrGenerate(cfg SelfSignedConfig) (*tls.Certificate, error) {
	if cfg.CacheDir == "" {
		return nil, fmt.Errorf("tlsmode: SelfSignedConfig.CacheDir is required")
	}
	if cfg.Validity == 0 {
		cfg.Validity = 365 * 24 * time.Hour
	}
	certPath := filepath.Join(cfg.CacheDir, "selfsigned.crt")
	keyPath := filepath.Join(cfg.CacheDir, "selfsigned.key")

	if c, err := loadCached(certPath, keyPath); err == nil {
		return c, nil
	}

	if err := os.MkdirAll(cfg.CacheDir, 0o700); err != nil {
		return nil, fmt.Errorf("tlsmode: create cache dir: %w", err)
	}
	cert, err := generate(cfg)
	if err != nil {
		return nil, err
	}
	if err := writeCached(cert, certPath, keyPath); err != nil {
		return nil, fmt.Errorf("tlsmode: cache cert: %w", err)
	}
	return cert, nil
}

func loadCached(certPath, keyPath string) (*tls.Certificate, error) {
	c, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(c.Certificate[0])
	if err != nil {
		return nil, err
	}
	// 14-day soft expiry — plenty of headroom for an operator who
	// runs the binary irregularly to still benefit from the cache.
	if time.Until(leaf.NotAfter) < 14*24*time.Hour {
		return nil, fmt.Errorf("cached cert expires too soon: %s", leaf.NotAfter)
	}
	c.Leaf = leaf
	return &c, nil
}

func generate(cfg SelfSignedConfig) (*tls.Certificate, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("tlsmode: keygen: %w", err)
	}

	host := ""
	if len(cfg.Hostnames) == 0 {
		if h, err := os.Hostname(); err == nil {
			host = h
		}
	}
	dnsNames := append([]string{"localhost"}, cfg.Hostnames...)
	if host != "" {
		dnsNames = append(dnsNames, host)
	}
	ips := append([]net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback}, cfg.IPSANs...)

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("tlsmode: serial: %w", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "ztp-server self-signed"},
		NotBefore:             now.Add(-1 * time.Hour),
		NotAfter:              now.Add(cfg.Validity),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		DNSNames:              dnsNames,
		IPAddresses:           ips,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, fmt.Errorf("tlsmode: sign: %w", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("tlsmode: parse fresh cert: %w", err)
	}
	return &tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  priv,
		Leaf:        leaf,
	}, nil
}

func writeCached(c *tls.Certificate, certPath, keyPath string) error {
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.Certificate[0]})
	if err := os.WriteFile(certPath, certPEM, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.PrivateKey)
	if err != nil {
		return err
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return os.WriteFile(keyPath, keyPEM, 0o600)
}
