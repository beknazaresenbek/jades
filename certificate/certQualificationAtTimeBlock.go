package certificate

import "time"

type CertQualificationAtTimeBlock struct {
	ValidationTime     ValidationTime
	SigningCertificate CertificateWrapper
	AcceptableServices []TrustService
	Date               time.Time
}

func (cq *CertQualificationAtTimeBlock) Init() {
	if cq.ValidationTime == VTCertificateIssuanceTime {
		cq.Date = cq.SigningCertificate.GetNotBefore()
	}

	//filter := ServiceByDateFilter{date: cq.Date}
	//filteredServices := filter.Filter(cq.AcceptableServices)

}
