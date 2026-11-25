package certverify

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

const grace = 30 * 24 * time.Hour

func newCA(t *testing.T, notAfter time.Time) (*x509.Certificate, *rsa.PrivateKey, []byte) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ca"},
		NotBefore:             time.Now().AddDate(-5, 0, 0),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign,
		IsCA:                  true,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return ca, key, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func newDeviceCert(t *testing.T, ca *x509.Certificate, caKey *rsa.PrivateKey, notAfter time.Time) *x509.Certificate {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    notAfter.AddDate(-1, 0, 0),
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca, &key.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

func newExpiredLeafVerifier(t *testing.T, caPEM []byte) (*PoolVerifier, *ExpiredLeafVerifier) {
	t.Helper()
	pool, err := NewPoolVerifier(caPEM, nil, x509.ExtKeyUsageClientAuth)
	if err != nil {
		t.Fatal(err)
	}
	expired, err := NewExpiredLeafVerifier(pool, grace)
	if err != nil {
		t.Fatal(err)
	}
	return pool, expired
}

func TestExpiredLeafVerifierAcceptsWithinGrace(t *testing.T) {
	ca, caKey, caPEM := newCA(t, time.Now().AddDate(5, 0, 0))
	cert := newDeviceCert(t, ca, caKey, time.Now().AddDate(0, 0, -10))
	pool, expired := newExpiredLeafVerifier(t, caPEM)

	if err := pool.Verify(context.Background(), cert); err == nil {
		t.Error("want the pool verifier to reject an expired certificate")
	}
	if err := NewFallbackVerifier(pool, expired).Verify(context.Background(), cert); err != nil {
		t.Errorf("want an expired certificate accepted within grace, got %v", err)
	}
}

func TestExpiredLeafVerifierRejectsBeyondGrace(t *testing.T) {
	ca, caKey, caPEM := newCA(t, time.Now().AddDate(5, 0, 0))
	cert := newDeviceCert(t, ca, caKey, time.Now().AddDate(0, 0, -40))
	_, expired := newExpiredLeafVerifier(t, caPEM)

	if err := expired.Verify(context.Background(), cert); err == nil {
		t.Error("want an error for a certificate expired beyond grace")
	}
}

func TestExpiredLeafVerifierRejectsForeignCA(t *testing.T) {
	_, _, caPEM := newCA(t, time.Now().AddDate(5, 0, 0))
	foreignCA, foreignKey, _ := newCA(t, time.Now().AddDate(5, 0, 0))
	cert := newDeviceCert(t, foreignCA, foreignKey, time.Now().AddDate(0, 0, -10))
	_, expired := newExpiredLeafVerifier(t, caPEM)

	if err := expired.Verify(context.Background(), cert); err == nil {
		t.Error("want an error for a certificate from a foreign CA")
	}
}

func TestExpiredLeafVerifierRejectsExpiredCA(t *testing.T) {
	ca, caKey, caPEM := newCA(t, time.Now().AddDate(0, 0, -5))
	cert := newDeviceCert(t, ca, caKey, time.Now().AddDate(0, 0, -10))
	_, expired := newExpiredLeafVerifier(t, caPEM)

	if err := expired.Verify(context.Background(), cert); err == nil {
		t.Error("want an error for a certificate whose CA has expired")
	}
}

func TestExpiredLeafVerifierRejectsValidCert(t *testing.T) {
	ca, caKey, caPEM := newCA(t, time.Now().AddDate(5, 0, 0))
	cert := newDeviceCert(t, ca, caKey, time.Now().AddDate(0, 1, 0))
	_, expired := newExpiredLeafVerifier(t, caPEM)

	if err := expired.Verify(context.Background(), cert); err == nil {
		t.Error("want the expired leaf verifier to leave valid certificates to the pool verifier")
	}
}
