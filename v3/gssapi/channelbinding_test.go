package gssapi

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func createTestCert(t *testing.T, sigAlg x509.SignatureAlgorithm) *x509.Certificate {
	t.Helper()
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SignatureAlgorithm: sigAlg,
		SerialNumber:       big.NewInt(1),
		Subject:            pkix.Name{Organization: []string{"Test"}},
		NotBefore:          time.Now(),
		NotAfter:           time.Now().Add(24 * time.Hour),
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create cert: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

func TestCertificateHash(t *testing.T) {
	tests := []struct {
		name    string
		sigAlg  x509.SignatureAlgorithm
		hashLen int // expected hash output length
		wantNil bool
	}{
		{"SHA256WithRSA", x509.SHA256WithRSA, 32, false},
		{"SHA384WithRSA", x509.SHA384WithRSA, 48, false},
		{"SHA512WithRSA", x509.SHA512WithRSA, 64, false},
		{"SHA1WithRSA (fallback to SHA256)", x509.SHA1WithRSA, 32, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cert := createTestCert(t, tt.sigAlg)
			hash := CertificateHash(cert)
			if tt.wantNil {
				if hash != nil {
					t.Errorf("expected nil hash, got %d bytes", len(hash))
				}
				return
			}
			if hash == nil {
				t.Fatal("expected non-nil hash")
			}
			if len(hash) != tt.hashLen {
				t.Errorf("expected %d byte hash, got %d", tt.hashLen, len(hash))
			}
		})
	}
}

func TestComputeChannelBindingHash(t *testing.T) {
	cert := createTestCert(t, x509.SHA256WithRSA)
	certHash := CertificateHash(cert)
	if certHash == nil {
		t.Fatal("expected non-nil cert hash")
	}

	cbHash := ComputeChannelBindingHash(certHash)

	// Result must be 16 bytes (MD5)
	if len(cbHash) != 16 {
		t.Fatalf("expected 16 byte hash, got %d", len(cbHash))
	}

	// Must not be all zeros
	allZero := true
	for _, b := range cbHash {
		if b != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Error("channel binding hash is all zeros")
	}

	// Same input must produce same output (deterministic)
	cbHash2 := ComputeChannelBindingHash(certHash)
	if cbHash != cbHash2 {
		t.Error("same input produced different hashes")
	}
}

func TestComputeChannelBindingHashDifferentCerts(t *testing.T) {
	cert1 := createTestCert(t, x509.SHA256WithRSA)
	cert2 := createTestCert(t, x509.SHA256WithRSA)

	hash1 := ComputeChannelBindingHash(CertificateHash(cert1))
	hash2 := ComputeChannelBindingHash(CertificateHash(cert2))

	if hash1 == hash2 {
		t.Error("different certs produced same channel binding hash")
	}
}
