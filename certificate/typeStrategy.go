package certificate

type TypeStrategy interface {
	GetType() CertType
}

type TypeByCertificatePostEIDAS struct {
	signingCertificate *CertificateWrapper
}

func (t *TypeByCertificatePostEIDAS) GetType() CertType {
	eSign := IsQcTypeESign(t.signingCertificate)
	eSeal := IsQcTypeESeal(t.signingCertificate)
	web := IsQcTypeWeb(t.signingCertificate)

	noneType := !(eSign || eSeal || web)

	counter := 0
	for _, qcType := range []bool{eSign, eSeal, web} {
		if qcType {
			counter++
		}
	}
	onlyOne := counter == 1

	if noneType && t.signingCertificate.isQcCompliance() || eSign && onlyOne {
		return CertTypeESign
	} else if eSeal && onlyOne {
		return CertTypeESeal
	} else if web && onlyOne {
		return CertTypeWSA
	} else {
		return CertTypeUnknown
	}
}

type TypeByCertificatePreEIDAS struct {
	signingCertificate *CertificateWrapper
}

func (t *TypeByCertificatePreEIDAS) GetType() CertType {
	if t.signingCertificate.isQcCompliance() || IsQCP(t.signingCertificate) || IsQCPPlus(t.signingCertificate) {
		return CertTypeESign
	} else {
		return CertTypeUnknown
	}
}

type TypeByTL struct {
	trustService *TrustService
	qualified    QualifiedStatus
	typeInCert   TypeStrategy
}

func (t *TypeByTL) GetType() CertType {
	if t.qualified == QualifiedStatusQC {
		if t.trustService == nil {
			return CertTypeUnknown
		}

		startDate := t.trustService.GetStartDate()
		if !IsPostEIDAS(*startDate) {
			return CertTypeESign
		}

		usageQualifiers := FilterUsageQualifiers(t.trustService.GetQualifiers())

		if len(usageQualifiers) > 1 {
			return CertTypeUnknown
		} else if len(usageQualifiers) == 1 {
			if IsQcForESig(usageQualifiers) {
				return CertTypeESign
			} else if IsQcForESeal(usageQualifiers) {
				return CertTypeESeal
			} else if IsQcForWSA(usageQualifiers) {
				return CertTypeWSA
			}
		}
	}
	return t.typeInCert.GetType()
}

func CreateTypeFromCert(signingCertificate *CertificateWrapper) TypeStrategy {
	if IsPostEIDAS(signingCertificate.GetNotBefore()) {
		return &TypeByCertificatePostEIDAS{signingCertificate}
	} else {
		return &TypeByCertificatePreEIDAS{signingCertificate}
	}
}

func createTypeFromTL(trustService *TrustService, qualified QualifiedStatus, typeInCert TypeStrategy) TypeStrategy {
	return &TypeByTL{trustService, qualified, typeInCert}
}

func CreateTypeFromCertAndTL(signingCertificate *CertificateWrapper, caQcTrustService *TrustService,
	qualified QualifiedStatus) TypeStrategy {
	return createTypeFromTL(caQcTrustService, qualified, CreateTypeFromCert(signingCertificate))
}
