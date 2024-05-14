package certificate

import "time"

type TrustServiceFinder interface {
	FindCatching(certificate *CertificateWrapper, validationTime ValidationTime) *TrustService
}

type TrustServiceFinderImpl struct{}

func (tsf *TrustServiceFinderImpl) FindCatching(certificate *CertificateWrapper, validationTime ValidationTime) *TrustService {
	var date time.Time
	if validationTime == VTCertificateIssuanceTime {
		date = certificate.GetNotBefore()
	} else {
		date = time.Now()
	}

	trustServices := certificate.GetTrustServices()

	acceptableTLUrls := GetAcceptableTLUrls(trustServices)

	acceptableServices := Filter(&ServiceByTLUrlFilter{acceptableTLUrls}, trustServices)

	filteredServices := Filter(&ServiceByDateFilter{date}, acceptableServices)

	caqcServices := Filter(&CaQcServiceFilter{}, filteredServices)
	if len(caqcServices) > 0 {
		filteredServices = caqcServices
	}

	filteredServices = Filter(&ServiceByCertificateTypeFilter{certificate}, filteredServices)

	filteredServices = Filter(&ServiceConsistencyFilter{}, filteredServices)

	grantedServices := Filter(&GrantedServiceFilter{}, filteredServices)
	if len(grantedServices) > 0 {
		filteredServices = grantedServices
	}

	filteredServices = Filter(&ServiceConsistencyFilter{}, filteredServices)

	if len(filteredServices) > 0 {
		return &filteredServices[0]
	} else {
		return nil
	}
}
