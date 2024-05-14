package certificate

type QSCDStrategy interface {
	GetQSCDStatus() QSCDStatus
}

type QSCDByCertificatePostEIDAS struct {
	certificate *CertificateWrapper
}

func (q *QSCDByCertificatePostEIDAS) GetQSCDStatus() QSCDStatus {
	if q.certificate.IsSupportedByQSCD() {
		return QSCDStatusQSCD
	} else {
		return QSCDStatusNotQSCD
	}
}

type QSCDByCertificatePreEIDAS struct {
	certificate *CertificateWrapper
}

func (q *QSCDByCertificatePreEIDAS) GetQSCDStatus() QSCDStatus {
	if IsQCPPlus(q.certificate) || q.certificate.IsSupportedByQSCD() {
		return QSCDStatusQSCD
	} else {
		return QSCDStatusNotQSCD
	}
}

type QSCDByTL struct {
	trustService        *TrustService
	qualified           QualifiedStatus
	qscdFromCertificate QSCDStrategy
}

func (q *QSCDByTL) GetQSCDStatus() QSCDStatus {
	if q.trustService == nil || q.qualified != QualifiedStatusNotQC {
		return QSCDStatusNotQSCD
	} else {
		qualifiers := q.trustService.GetQualifiers()
		startDate := q.trustService.GetStartDate()
		if IsPostEIDAS(*startDate) {
			if IsQcWithQSCD(qualifiers) || IsQcQSCDManagedOnBehalf(qualifiers) {
				return QSCDStatusQSCD
			} else if IsQcQSCDStatusAsInCert(qualifiers) {
				return q.qscdFromCertificate.GetQSCDStatus()
			} else if IsQcNoQSCD(qualifiers) {
				return QSCDStatusNotQSCD
			}
		} else {
			if IsQcWithSSCD(qualifiers) {
				return QSCDStatusQSCD
			} else if IsQcSSCDStatusAsInCert(qualifiers) {
				return q.qscdFromCertificate.GetQSCDStatus()
			} else if IsQcNoSSCD(qualifiers) {
				return QSCDStatusNotQSCD
			}
		}
	}
	return q.qscdFromCertificate.GetQSCDStatus()
}

func createQSCDFromCert(signingCertificate *CertificateWrapper) QSCDStrategy {
	if IsPostEIDAS(signingCertificate.GetNotBefore()) {
		return &QSCDByCertificatePostEIDAS{certificate: signingCertificate}
	} else {
		return &QSCDByCertificatePreEIDAS{certificate: signingCertificate}
	}
}

func createQSCDFromTL(trustService *TrustService, qualified QualifiedStatus,
	qscdFromCertificate QSCDStrategy) QSCDStrategy {
	return &QSCDByTL{trustService, qualified, qscdFromCertificate}
}

func CreateQSCDFromCertAndTL(signingCertificate *CertificateWrapper, caQcTrustService *TrustService,
	qualified QualifiedStatus) QSCDStrategy {
	return createQSCDFromTL(caQcTrustService, qualified, createQSCDFromCert(signingCertificate))
}
