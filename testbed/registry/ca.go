// Copyright (c) 2026 Rhythm Shahriar <me@rhy.io>
// SPDX-License-Identifier: MIT

package registry

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
	"time"
)

// certAuthority is a throwaway CA generated for one run. It signs the
// loopback leaf certificate every TLS listener serves; its PEM is
// written to testbed/state/ca.pem so a Sightread run can trust it with
// SSL_CERT_FILE. Nothing about it is secret: it is valid only for
// 127.0.0.1 and lives only for the run.
type certAuthority struct {
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
	certPEM []byte
	leaf    tls.Certificate
}

// newCA generates a CA and a loopback leaf certificate.
func newCA() (*certAuthority, error) {
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	caTmpl := &x509.Certificate{
		SerialNumber:          serial(),
		Subject:               pkix.Name{CommonName: "Sightread testbed CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, err
	}
	ca := &certAuthority{
		cert:    caCert,
		key:     caKey,
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER}),
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	leafTmpl := &x509.Certificate{
		SerialNumber: serial(),
		Subject:      pkix.Name{CommonName: "127.0.0.1"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		DNSNames:     []string{"localhost"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		return nil, err
	}
	ca.leaf = tls.Certificate{Certificate: [][]byte{leafDER}, PrivateKey: leafKey, Leaf: leafTmpl}
	return ca, nil
}

// tlsConfig returns a server TLS config serving the loopback leaf.
func (ca *certAuthority) tlsConfig() *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{ca.leaf},
		MinVersion:   tls.VersionTLS12,
	}
}

// writePEM writes the CA certificate to path.
func (ca *certAuthority) writePEM(path string) error {
	if err := os.WriteFile(path, ca.certPEM, 0o644); err != nil { //nolint:gosec // a public CA cert, not a secret
		return fmt.Errorf("write ca.pem: %w", err)
	}
	return nil
}

// serial makes a random certificate serial number.
func serial() *big.Int {
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		panic(err)
	}
	return n
}
