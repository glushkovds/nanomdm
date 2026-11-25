package certverify

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"time"
)

// ExpiredLeafVerifier accepts a device certificate that expired no longer than
// maxExpired ago. Only the leaf NotAfter is relaxed: the chain, the CA validity,
// the key usage and NotBefore are verified as usual at the current time.
type ExpiredLeafVerifier struct {
	base       *PoolVerifier
	maxExpired time.Duration
	now        func() time.Time
}

// NewExpiredLeafVerifier creates a new verifier on top of the base verifier options.
func NewExpiredLeafVerifier(base *PoolVerifier, maxExpired time.Duration) (*ExpiredLeafVerifier, error) {
	if base == nil {
		return nil, errors.New("nil base verifier")
	}
	if maxExpired <= 0 {
		return nil, errors.New("maxExpired must be greater than zero")
	}
	return &ExpiredLeafVerifier{
		base:       base,
		maxExpired: maxExpired,
		now:        time.Now,
	}, nil
}

// Verify performs certificate verification
func (v *ExpiredLeafVerifier) Verify(_ context.Context, cert *x509.Certificate) error {
	if cert == nil {
		return errors.New("missing MDM certificate")
	}
	now := v.now()
	if !now.After(cert.NotAfter) {
		return errors.New("certificate is not expired")
	}
	if expiredFor := now.Sub(cert.NotAfter); expiredFor > v.maxExpired {
		return fmt.Errorf("certificate expired too long ago: expired for %s, max %s", expiredFor, v.maxExpired)
	}
	leaf := *cert
	leaf.NotAfter = now.Add(time.Minute)
	opts := v.base.verifyOpts
	opts.CurrentTime = now
	if _, err := leaf.Verify(opts); err != nil {
		return fmt.Errorf("expired leaf verification: %w", err)
	}
	return nil
}
