package certificate

import "github.com/google/go-cmp/cmp"

type QualificationCalculator struct {
	Certificate *CertificateWrapper
}

type FinalQualificationCalculator struct {
	CertQualificationAtIssuanceTime *Qualification
	CertQualificationAtSigningTime  *Qualification
}

func (qc *QualificationCalculator) GetQualification(caqcTrustService *TrustService) Qualification {
	qcStrategy := CreateQualificationFromCertAndTL(qc.Certificate, caqcTrustService)
	qualifiedStatus := qcStrategy.GetQualifiedStatus()

	typeStrategy := CreateTypeFromCertAndTL(qc.Certificate, caqcTrustService, qualifiedStatus)

	qscdStrategy := CreateQSCDFromCertAndTL(qc.Certificate, caqcTrustService, qualifiedStatus)

	return getCertQualification(qualifiedStatus, typeStrategy.GetType(), qscdStrategy.GetQSCDStatus())
}

func getCertQualification(status QualifiedStatus, certType CertType, qscd QSCDStatus) Qualification {
	return Qualification{qualifiedStatus: status, certType: certType, qscdStatus: qscd}
}

func (fqc *FinalQualificationCalculator) GetFinalQualification() *Qualification {
	if cmp.Equal(fqc.CertQualificationAtIssuanceTime, fqc.CertQualificationAtSigningTime) {
		return fqc.CertQualificationAtIssuanceTime
	}

	if cmp.Equal(fqc.CertQualificationAtIssuanceTime, QualificationNA) || cmp.Equal(fqc.CertQualificationAtSigningTime, QualificationNA) {
		return &QualificationNA
	}

	qualificationStatus := fqc.getFinalCertQualificationStatus()
	certType := fqc.getFinalCertType()
	qscdStatus := fqc.getFinalQSCDStatus()

	return &Qualification{qualifiedStatus: qualificationStatus, certType: certType, qscdStatus: qscdStatus}
}

func (fqc *FinalQualificationCalculator) getFinalCertQualificationStatus() QualifiedStatus {
	if fqc.CertQualificationAtIssuanceTime.IsQC() && fqc.CertQualificationAtSigningTime.IsQC() {
		return QualifiedStatusQC
	} else {
		return QualifiedStatusNotQC
	}
}

func (fqc *FinalQualificationCalculator) getFinalCertType() CertType {
	if fqc.CertQualificationAtSigningTime.GetCertType() == fqc.CertQualificationAtIssuanceTime.GetCertType() {
		return fqc.CertQualificationAtSigningTime.GetCertType()
	} else {
		return CertTypeUnknown
	}
}

func (fqc *FinalQualificationCalculator) getFinalQSCDStatus() QSCDStatus {
	if fqc.CertQualificationAtSigningTime.IsQSCD() {
		return QSCDStatusQSCD
	} else {
		return QSCDStatusNotQSCD
	}
}
