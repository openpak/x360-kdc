package xuacs

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// LoadOrCreateKey reads an RSA-2048 private key PEM (PKCS#1 or PKCS#8). When the
// file is missing a new key is generated and written 0600.
func LoadOrCreateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		k, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			return nil, err
		}
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		pemb := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)})
		tmp := path + ".tmp"
		if err := os.WriteFile(tmp, pemb, 0o600); err != nil {
			return nil, err
		}
		return k, os.Rename(tmp, path)
	}
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
	if err != nil {
		var any interface{}
		if any, err = x509.ParsePKCS8PrivateKey(blk.Bytes); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		var ok bool
		if k, ok = any.(*rsa.PrivateKey); !ok {
			return nil, fmt.Errorf("%s: not an RSA key", path)
		}
	}
	if k.N.BitLen() != 2048 {
		return nil, fmt.Errorf("%s: key is %d bits, want 2048", path, k.N.BitLen())
	}
	return k, nil
}
