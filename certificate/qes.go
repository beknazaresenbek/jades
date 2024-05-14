package certificate

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"jades/logging"
)

type ElsiVerificationService struct {
}

type EIDASCertificate struct {
	certificate *x509.Certificate
}

func LoadCertificate2(encoded string) (*EIDASCertificate, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		logging.Log().Error("base64 decode failed")
	}

	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		logging.Log().Error("cert read failed")
		return nil, err
	}
	return &EIDASCertificate{certificate: certificate}, nil
}

func (v *EIDASCertificate) IsSignedBy(publicKey *rsa.PublicKey) error {
	h := sha256.New()
	h.Write(v.certificate.RawTBSCertificate)
	hashData := h.Sum(nil)

	err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, hashData, v.certificate.Signature)
	if err != nil {
		return err
	}

	return nil
}

func (c *EIDASCertificate) PublicKey() *rsa.PublicKey {
	return c.certificate.PublicKey.(*rsa.PublicKey)
}

func (c *EIDASCertificate) IsQualified() bool {
	return false
}
