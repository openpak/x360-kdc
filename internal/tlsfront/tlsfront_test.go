package tlsfront

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

// XAM offers RSA key exchange only; the server must pick an RSA AES-CBC suite
// and present a leaf for the requested name.
func TestRSAKeyExchangeLeaf(t *testing.T) {
	f, err := LoadOrCreate(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") }))
	f.Serve(srv.Config)
	srv.TLS = srv.Config.TLSConfig
	srv.StartTLS()
	defer srv.Close()
	for _, suite := range []uint16{tls.TLS_RSA_WITH_AES_128_CBC_SHA256, tls.TLS_RSA_WITH_AES_128_CBC_SHA} {
		conn, err := tls.Dial("tcp", srv.Listener.Addr().String(), &tls.Config{
			ServerName: "login.live.com", InsecureSkipVerify: true,
			MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS12, CipherSuites: []uint16{suite},
		})
		if err != nil {
			t.Fatalf("suite %#04x: %v", suite, err)
		}
		st := conn.ConnectionState()
		if st.CipherSuite != suite || len(st.PeerCertificates) != 1 || st.PeerCertificates[0].Subject.CommonName != "login.live.com" {
			t.Fatalf("suite %#04x: got %#04x, %d certs", suite, st.CipherSuite, len(st.PeerCertificates))
		}
		if st.PeerCertificates[0].NotAfter.Year() >= 2050 {
			t.Fatal("notAfter must stay UTCTime")
		}
		conn.Close()
	}
}
