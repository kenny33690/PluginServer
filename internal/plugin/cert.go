package plugin

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"
	"time"
)

type CertInfo struct {
	Subject   string
	NotBefore time.Time
	NotAfter  time.Time
}

type Validator struct {
	roots *x509.CertPool
	now   func() time.Time
}

func NewValidator(rootCAPath string) (*Validator, error) {
	caPEM, err := os.ReadFile(rootCAPath)
	if err != nil {
		return nil, fmt.Errorf("read root ca: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(caPEM) {
		return nil, fmt.Errorf("append root ca: no valid certificate found")
	}

	return &Validator{
		roots: pool,
		now:   time.Now,
	}, nil
}

func (v *Validator) ValidatePluginCert(name string, certString string) (CertInfo, error) {
	cert, err := parseCertificate(certString)
	if err != nil {
		return CertInfo{}, err
	}

	if cert.Subject.CommonName != name {
		return CertInfo{}, fmt.Errorf("certificate subject common name %q does not match name %q", cert.Subject.CommonName, name)
	}

	now := v.now()
	if now.Before(cert.NotBefore) || now.After(cert.NotAfter) {
		return CertInfo{}, fmt.Errorf("certificate is outside its validity period")
	}

	if _, err := cert.Verify(x509.VerifyOptions{
		Roots:       v.roots,
		CurrentTime: now,
	}); err != nil {
		return CertInfo{}, fmt.Errorf("verify certificate chain: %w", err)
	}

	return CertInfo{
		Subject:   cert.Subject.String(),
		NotBefore: cert.NotBefore,
		NotAfter:  cert.NotAfter,
	}, nil
}

func parseCertificate(certString string) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(strings.TrimSpace(certString)))
	if block == nil {
		return nil, fmt.Errorf("decode certificate pem: invalid PEM data")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return cert, nil
}
