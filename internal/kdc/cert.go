package kdc

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/x509"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
)

// The OpenPak console certificate: 424 bytes, the keyvault 0x36 layout.
//
//	0x00  2  BE size 0x01A8        0x02  5  console ID
//	0x07 11  part number           0x12  4  reserved
//	0x16  2  BE privileges         0x18  4  BE console type
//	0x1C  8  manufacture date      0x24  4  BE RSA exponent
//	0x28 128 BE RSA-1024 modulus   0xA8 256 CA signature over [0,0xA8)
const (
	CertLen       = 424
	certSigned    = 0xa8
	certIDOff     = 0x02
	certExpOff    = 0x24
	certModOff    = 0x28
	certModLen    = 128
	caSaltLen     = 10
	consoleSigLen = 128
)

var certHeader = []byte{0x01, 0xa8}

// VerifyCA checks the certificate's shape and its CA signature: RSA-2048 PSS,
// SHA1, MGF1-SHA1, salt length 10, over cert[0:0xA8]. This is OpenPak's dev
// provisioning format; Microsoft's own signatures are not accepted.
func VerifyCA(ca *rsa.PublicKey, cert []byte) error {
	if len(cert) != CertLen || cert[0] != certHeader[0] || cert[1] != certHeader[1] {
		return errors.New("certificate header")
	}
	digest := sha1.Sum(cert[:certSigned])
	opts := &rsa.PSSOptions{SaltLength: caSaltLen, Hash: crypto.SHA1}
	if err := rsa.VerifyPSS(ca, crypto.SHA1, digest[:], cert[certSigned:], opts); err != nil {
		return errors.New("CA signature")
	}
	return nil
}

// consolePublicKey reads the RSA-1024 key embedded in a verified certificate.
func consolePublicKey(cert []byte) (*rsa.PublicKey, error) {
	e := binary.BigEndian.Uint32(cert[certExpOff:])
	if e == 0 || e > 1<<31-1 {
		return nil, errors.New("console key exponent")
	}
	n := new(big.Int).SetBytes(cert[certModOff : certModOff+certModLen])
	if n.BitLen() != certModLen*8 {
		return nil, errors.New("console key modulus")
	}
	return &rsa.PublicKey{N: n, E: int(e)}, nil
}

// ConsoleID is the 5-byte console ID as a big-endian number.
func ConsoleID(cert []byte) uint64 {
	var b [8]byte
	copy(b[3:], cert[certIDOff:certIDOff+5])
	return binary.BigEndian.Uint64(b[:])
}

// ConsoleDigits is the 12-decimal-digit form the firmware puts in names:
// console ID modulo 10^12, zero padded.
func ConsoleDigits(cert []byte) string {
	return fmt.Sprintf("%012d", ConsoleID(cert)%1000000000000)
}

// LoadPrivateKey reads an RSA private key PEM (PKCS#8 or PKCS#1).
func LoadPrivateKey(path string) (*rsa.PrivateKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	switch blk.Type {
	case "PRIVATE KEY":
		k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r, ok := k.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA key", path)
		}
		return r, nil
	case "RSA PRIVATE KEY":
		k, err := x509.ParsePKCS1PrivateKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, nil
	}
	return nil, fmt.Errorf("%s: unexpected PEM type %q", path, blk.Type)
}

// LoadPublicKey reads an RSA public key PEM (PKIX "PUBLIC KEY" or PKCS#1).
func LoadPublicKey(path string) (*rsa.PublicKey, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, fmt.Errorf("%s: no PEM block", path)
	}
	switch blk.Type {
	case "PUBLIC KEY":
		k, err := x509.ParsePKIXPublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		r, ok := k.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("%s: not an RSA key", path)
		}
		return r, nil
	case "RSA PUBLIC KEY":
		k, err := x509.ParsePKCS1PublicKey(blk.Bytes)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		return k, nil
	}
	return nil, fmt.Errorf("%s: unexpected PEM type %q", path, blk.Type)
}
