package dsig

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
)

//Well-known errors
var (
	ErrNonRSAKey           = fmt.Errorf("Private key was not RSA")
	ErrMissingCertificates = fmt.Errorf("No public certificates provided")
)

//TLSCertKeyStore wraps the stdlib tls.Certificate to return its contained key
//and certs.
type TLSCertKeyStore tls.Certificate

//GetKeyPair implements X509KeyStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetKeyPair() (*rsa.PrivateKey, *x509.Certificate, error) {
	pk, ok := d.PrivateKey.(*rsa.PrivateKey)

	if !ok {
		return nil, nil, ErrNonRSAKey
	}

	if len(d.Certificate) < 1 {
		return nil, nil, ErrMissingCertificates
	}

	crt, err := x509.ParseCertificate(d.Certificate[0])
	if err != nil {
		return nil, nil, ErrMissingCertificates
	}

	return pk, crt, nil
}

//GetChain impliments X509ChainStore using the underlying tls.Certificate
func (d TLSCertKeyStore) GetChain() ([]*x509.Certificate, error) {
	certs := []*x509.Certificate{}
	for _, cert := range d.Certificate {
		c, err := x509.ParseCertificate(cert)
		if err != nil {
			continue
		}
		certs = append(certs, c)
	}

	return certs, nil
}
