package cryptoutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/smallstep/pkcs7"
)

func signedByExpiredCert(t *testing.T, body []byte) (string, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "device"},
		NotBefore:    time.Now().AddDate(-1, -1, 0),
		NotAfter:     time.Now().AddDate(0, -1, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	sd, err := pkcs7.NewSignedData(body)
	if err != nil {
		t.Fatal(err)
	}
	if err = sd.AddSigner(cert, key, pkcs7.SignerInfoConfig{}); err != nil {
		t.Fatal(err)
	}
	sd.Detach()
	sig, err := sd.Finish()
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(sig), cert
}

func TestVerifyMdmSignatureRejectsExpiredCert(t *testing.T) {
	body := []byte("checkin")
	header, _ := signedByExpiredCert(t, body)

	_, err := VerifyMdmSignature(header, body)

	var signingTimeErr *pkcs7.SigningTimeNotValidError
	if !errors.As(err, &signingTimeErr) {
		t.Fatalf("want signing time error, got %v", err)
	}
}

func TestVerifyMdmSignatureAllowExpiredReturnsOriginalCert(t *testing.T) {
	body := []byte("checkin")
	header, signer := signedByExpiredCert(t, body)

	cert, err := VerifyMdmSignatureAllowExpired(header, body)

	if err != nil {
		t.Fatal(err)
	}
	if !cert.Equal(signer) || !cert.NotAfter.Equal(signer.NotAfter) {
		t.Error("want the original signer certificate")
	}
}

func TestVerifyMdmSignatureAllowExpiredRejectsTamperedBody(t *testing.T) {
	header, _ := signedByExpiredCert(t, []byte("checkin"))

	_, err := VerifyMdmSignatureAllowExpired(header, []byte("tampered"))

	if err == nil {
		t.Error("want an error for a body that does not match the signature")
	}
}
