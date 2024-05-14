package certificate

type QualificationStrategy interface {
	GetQualifiedStatus() QualifiedStatus
}

type QualificationByCertificatePostEIDAS struct {
	signingCertificate *CertificateWrapper
}

func (qs *QualificationByCertificatePostEIDAS) GetQualifiedStatus() QualifiedStatus {
	if qs.signingCertificate.isQcCompliance() {
		return QualifiedStatusQC
	} else {
		return QualifiedStatusNotQC
	}
}

type QualificationByCertificatePreEIDAS struct {
	signingCertificate *CertificateWrapper
}

func (qs *QualificationByCertificatePreEIDAS) GetQualifiedStatus() QualifiedStatus {
	if qs.signingCertificate.isQcCompliance() || IsQCP(qs.signingCertificate) || IsQCPPlus(qs.signingCertificate) {
		return QualifiedStatusQC
	} else {
		return QualifiedStatusNotQC
	}
}

type QualificationByTL struct {
	trustService    *TrustService
	qualifiedInCert QualificationStrategy
}

func (qs *QualificationByTL) GetQualifiedStatus() QualifiedStatus {
	if qs.trustService == nil {
		return QualifiedStatusNotQC
	} else {
		grantedFilter := GrantedServiceFilter{}
		if !grantedFilter.isAcceptable(qs.trustService) {
			return QualifiedStatusNotQC
		}

		qualifiers := qs.trustService.GetQualifiers()
		if len(qualifiers) > 0 {
			if IsNotQualified(qualifiers) {
				return QualifiedStatusNotQC
			}
			if IsQCStatement(qualifiers) {
				return QualifiedStatusQC
			}
		}

		return qs.qualifiedInCert.GetQualifiedStatus()
	}
}

func createQualificationFromCert(signingCertificate *CertificateWrapper) QualificationStrategy {
	if IsPostEIDAS(signingCertificate.GetNotBefore()) {
		return &QualificationByCertificatePostEIDAS{signingCertificate}
	} else {
		return &QualificationByCertificatePreEIDAS{signingCertificate}
	}
}

func createQualificationFromTL(trustService *TrustService, qualifiedInCert QualificationStrategy) QualificationStrategy {
	return &QualificationByTL{trustService, qualifiedInCert}
}

func CreateQualificationFromCertAndTL(signingCertificate *CertificateWrapper, caQcTrustService *TrustService) QualificationStrategy {
	return createQualificationFromTL(caQcTrustService, createQualificationFromCert(signingCertificate))
}
