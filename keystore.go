package dsig

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"math/big"
	"time"
)

// X509KeyStore is elemetary type. This package can be leveraged by implimenting GetKeyPair method.
type X509KeyStore interface {
	GetKeyPair() (privateKey *rsa.PrivateKey, cert *x509.Certificate, err error)
}

// X509ChainStore interface.
type X509ChainStore interface {
	GetChain() (certs []*x509.Certificate, err error)
}

// X509CertificateStore interface.
type X509CertificateStore interface {
	Certificates() (roots []*x509.Certificate, err error)
}

// MemoryX509CertificateStore interface.
type MemoryX509CertificateStore struct {
	Roots []*x509.Certificate
}

// Certificates retruns list of certificates.
func (mX509cs *MemoryX509CertificateStore) Certificates() ([]*x509.Certificate, error) {
	return mX509cs.Roots, nil
}

// MemoryX509KeyStore used for testing and all.
type MemoryX509KeyStore struct {
	privateKey *rsa.PrivateKey
	cert       []byte
}

// GetKeyPair implimenting X509KeyStore interface.
func (ks *MemoryX509KeyStore) GetKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	cert, err := x509.ParseCertificate(ks.cert)
	if err != nil {
		return nil, nil, err
	}
	return ks.privateKey, cert, nil
}

// RandomKeyStoreForTest is for generating test key.
func RandomKeyStoreForTest() X509KeyStore {
	key, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		panic(err)
	}

	now := time.Now()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(0),
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.Add(365 * 24 * time.Hour),

		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{},
		BasicConstraintsValid: true,
	}

	cert, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}

	return &MemoryX509KeyStore{
		privateKey: key,
		cert:       cert,
	}
}
