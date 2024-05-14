package certificate

import "golang.org/x/exp/slices"

func IsQcTypeESign(certificate *CertificateWrapper) bool {
	return hasQcTypeOID(certificate, QcTypeESign)
}

func IsQcTypeESeal(certificate *CertificateWrapper) bool {
	return hasQcTypeOID(certificate, QcTypeESeal)
}

func IsQcTypeWeb(certificate *CertificateWrapper) bool {
	return hasQcTypeOID(certificate, QcTypeWeb)
}

func hasQcTypeOID(certificate *CertificateWrapper, qcType QcType) bool {
	return slices.Contains(certificate.qcStatements.QcTypes, qcType.oid)
}
