// Package tlsfront terminates the Xbox 360 XAM TLS client (the Windows Live ID
// login at nexus.passport.com / login.live.com). XAM's "Microsoft TLS"
// provider offers RSA key exchange only, so Traefik passes these SNIs through
// and this listener mints an exact leaf per requested name from the OpenPak
// CA the console trusts. Copied from np-account's tlsfront (same owner and
// licence); the two are kept separate on purpose (one service per console
// generation).
package tlsfront

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Front holds the CA and the per-name leaves minted from it.
type Front struct {
	ca      *x509.Certificate
	caKey   any
	leafKey *rsa.PrivateKey
	// Fallback names the leaf for a client that sends no SNI.
	Fallback string
	// Log, when set, receives each ClientHello's parameters.
	Log func(msg string, args ...any)

	mu    sync.Mutex
	cache map[string]*tls.Certificate // ponytail: unbounded; Traefik only passes the PS3 families through
}

// LoadOrCreate loads dir/ca.pem and dir/ca-key.pem, creating a self-signed
// RSA-2048 CA (0600, ten years) when they are missing.
func LoadOrCreate(dir string) (*Front, error) {
	certPath, keyPath := filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca-key.pem")
	if _, err := os.Stat(certPath); errors.Is(err, os.ErrNotExist) {
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		tpl := &x509.Certificate{
			SerialNumber:          big.NewInt(1),
			Subject:               pkix.Name{CommonName: "OpenPak Xbox 360 WLID CA", Organization: []string{"OpenPak"}},
			NotBefore:             time.Now().Add(-time.Hour),
			NotAfter:              time.Now().AddDate(10, 0, 0),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(dir, 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}), 0o600); err != nil {
			return nil, err
		}
		if err := os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600); err != nil {
			return nil, err
		}
	}
	return Load(certPath, keyPath)
}

// Load reads the CA certificate and key (PKCS#1 or PKCS#8 PEM).
func Load(certPath, keyPath string) (*Front, error) {
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, errors.New("tlsfront: CA certificate is not PEM")
	}
	ca, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	block, _ = pem.Decode(keyPEM)
	if block == nil {
		return nil, errors.New("tlsfront: CA key is not PEM")
	}
	var caKey any
	if caKey, err = x509.ParsePKCS1PrivateKey(block.Bytes); err != nil {
		if caKey, err = x509.ParsePKCS8PrivateKey(block.Bytes); err != nil {
			return nil, fmt.Errorf("tlsfront: CA key: %w", err)
		}
	}
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, err
	}
	return &Front{ca: ca, caKey: caKey, leafKey: leafKey, cache: map[string]*tls.Certificate{}}, nil
}

// Config is the server configuration the firmware can negotiate.
func (f *Front) Config() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
		// RSA key exchange with AES-CBC: XAM offers no ECDHE, and these need
		// only the AES-CBC, SHA-1/SHA-256 and RSA kernel exports (GCM and
		// SHA-384 suites would need XeCryptAesGcm*/XeCryptSha384* in Wharf).
		CipherSuites: []uint16{
			tls.TLS_RSA_WITH_AES_128_CBC_SHA256,
			tls.TLS_RSA_WITH_AES_128_CBC_SHA,
		},
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// Exactly as sent: the lab leaves kept the firmware's case
			// (IV0001-NPXS01001-00.auth...), and its name check may not fold it.
			if f.Log != nil {
				f.Log("tls client hello", "sni", hello.ServerName, "remote", hello.Conn.RemoteAddr().String(),
					"versions", fmt.Sprintf("%04x", hello.SupportedVersions), "suites", fmt.Sprintf("%04x", hello.CipherSuites),
					"sigalgs", fmt.Sprintf("%04x", hello.SignatureSchemes), "extensions", fmt.Sprintf("%04x", hello.Extensions))
			}
			name := strings.TrimSuffix(hello.ServerName, ".")
			if name == "" {
				name = f.Fallback
			}
			if name == "" {
				return nil, errors.New("tlsfront: no server name")
			}
			return f.leaf(name)
		},
	}
}

// Serve wraps srv for the firmware: HTTP/1.1 only. Go's automatic HTTP/2
// refuses a cipher list without ECDHE-GCM, and XAM never asks for h2.
func (f *Front) Serve(srv *http.Server) *http.Server {
	srv.TLSConfig = f.Config()
	srv.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	return srv
}

func (f *Front) leaf(host string) (*tls.Certificate, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if c, ok := f.cache[host]; ok {
		return c, nil
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 63))
	if err != nil {
		return nil, err
	}
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host, Organization: []string{"OpenPak"}},
		NotBefore:    time.Now().Add(-48 * time.Hour), // the guest clock may lag
		NotAfter:     time.Now().AddDate(2, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, f.ca, &f.leafKey.PublicKey, f.caKey)
	if err != nil {
		return nil, err
	}
	// Leaf only: XAM checks the name and dates of every certificate sent and
	// verifies no chain for these hosts.
	c := &tls.Certificate{Certificate: [][]byte{der}, PrivateKey: f.leafKey}
	f.cache[host] = c
	return c, nil
}

// Issued reports whether der is a certificate this front's CA signed (the
// answer XAM asks Live for through /xsig/ValidateCertificate.ashx).
func (f *Front) Issued(der []byte) bool {
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return false
	}
	return c.CheckSignatureFrom(f.ca) == nil
}
