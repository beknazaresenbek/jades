package certificate

import (
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"jades/logging"
	"time"

	"golang.org/x/crypto/cryptobyte"
	cryptobyteasn1 "golang.org/x/crypto/cryptobyte/asn1"
)

type CertificateRefWrapper struct {
}

func (crw *CertificateRefWrapper) IsDigestValuePresent() bool {
	return true
}

func (crw *CertificateRefWrapper) IsDigestValueMatch() bool {
	return true
}

func (crw *CertificateRefWrapper) IsIssuerSerialPresent() bool {
	return true
}

func (crw *CertificateRefWrapper) IsIssuerSerialMatch() bool {
	return true
}

type CertificateWrapper struct {
	certificate        *x509.Certificate
	qcStatements       *QcStatements
	selfSigned         bool
	TrustServiceFinder TrustServiceFinder
}

func LoadCertificate(encoded string) (*CertificateWrapper, error) {
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		logging.Log().Error("base64 decode failed")
	}

	certificate, err := x509.ParseCertificate(data)
	if err != nil {
		logging.Log().Error("cert read failed")
		return nil, err
	}
	cert := CertificateWrapper{certificate: certificate}
	cert.parseExtensions()
	return &cert, nil
}

func (cw *CertificateWrapper) GetTrustServices() []TrustService {
	return []TrustService{}
}

func (cw *CertificateWrapper) IsTrustedListReached() bool {
	return false
}

func (cw *CertificateWrapper) isQcCompliance() bool {
	return cw.qcStatements.QcCompliance
}

func (cw *CertificateWrapper) GetNotBefore() time.Time {
	return cw.certificate.NotBefore
}

func (cw *CertificateWrapper) IsSupportedByQSCD() bool {
	return cw.qcStatements.QcSSCD
}

func (cw *CertificateWrapper) GetPolicyIds() []string {
	var policyIds []string
	for _, policyId := range cw.certificate.PolicyIdentifiers {
		policyIds = append(policyIds, policyId.String())
	}
	return policyIds
}

func (cw *CertificateWrapper) GetOrganizationIdentifier() string {
	return ""
}

func (cw *CertificateWrapper) GetOrganizationName() string {
	return ""
}

func (cw *CertificateWrapper) GetIssuerAltName() string {
	return ""
}

func (cw *CertificateWrapper) parseExtensions() {
	for _, ext := range cw.certificate.Extensions {
		if ext.Id.String() == ExtensionQCStatements.oid {
			input := cryptobyte.String(ext.Value)
			if !input.ReadASN1(&input, cryptobyteasn1.SEQUENCE) {
				cw.qcStatements = &QcStatements{Raw: input}
			}
			return
		}
	}
	cw.readQcStatements(&cw.qcStatements.Raw)
}

func (cw *CertificateWrapper) readQcStatements(input *cryptobyte.String) {
	for !input.Empty() {
		if input.PeekASN1Tag(cryptobyteasn1.OBJECT_IDENTIFIER) {
			var oid asn1.ObjectIdentifier
			if input.ReadASN1ObjectIdentifier(&oid) {
				if oid.String() == QcStatementQcCompliance.oid {
					cw.qcStatements.QcCompliance = true
				} else if oid.String() == QcStatementQcSSCD.oid {
					cw.qcStatements.QcSSCD = true
				} else if oid.String() == QcStatementQcType.oid {
					cw.qcStatements.QcTypes = append([]string{"TODO"})
				}
			}
		} else if input.PeekASN1Tag(cryptobyteasn1.SEQUENCE) {
			var val cryptobyte.String
			if input.ReadASN1(&val, cryptobyteasn1.SEQUENCE) {
				cw.readQcStatements(&val)
			}
		} else {
			var t1 cryptobyte.String
			var t2 cryptobyteasn1.Tag
			input.ReadAnyASN1(&t1, &t2)
		}
	}
}

func (cw *CertificateWrapper) IsTrusted() bool {
	return false
}

func (cw *CertificateWrapper) IsTrustedChain() bool {
	return false
}

func (cw *CertificateWrapper) IsCertificateChainFromTrustedStore() bool {
	return false
}

// Returns the certificate's Distinguished Name (by RFC 2253)
func (cw *CertificateWrapper) getCertificateDN() string {
	return ""
}

func (cw *CertificateWrapper) getSubjectAlternativeNames() []string {
	return nil
}

func (cw *CertificateWrapper) getSubjectDistinguishedName() []DistinguishedName {
	return nil
}

func (cw *CertificateWrapper) AddSubjectDistinguishedName(name DistinguishedName) {

}

// Returns value of the permittedSubtrees field of nameConstraints certificate extension, when present
func (cw *CertificateWrapper) getPermittedSubtrees() []string {
	return nil
}

// Returns value of the excludedSubtrees field of nameConstraints certificate extension, when present
func (cw *CertificateWrapper) getExcludedSubtrees() []string {
	return nil
}

func (cw *CertificateWrapper) SetSelfSigned(value bool) {
	cw.selfSigned = value
}

func (cw *CertificateWrapper) IsSelfSigned() bool {
	return cw.selfSigned
}

func (cw *CertificateWrapper) AddCertificateExtension(extension CertificateExtension) {}

func (cw *CertificateWrapper) SetCertificateChain(certificateChain []CertificateChainItem) {

}
