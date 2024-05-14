package certificate

import (
	"strings"
	"time"
)

type TrustServiceFilter interface {
	Filter(trustServices []TrustService)
}

type TrustServiceCheck interface {
	isAcceptable(trustService *TrustService) bool
}

type ServiceByCertificateTypeFilter struct {
	certificate *CertificateWrapper
}

type ServiceByDateFilter struct {
	date time.Time
}

type CaQcServiceFilter struct {
}

type ServiceConsistencyFilter struct {
}

type GrantedServiceFilter struct{}

type ServiceByTLUrlFilter struct {
	tlUrls []string
}

func Filter(trustServiceCheck TrustServiceCheck, trustServices []TrustService) []TrustService {
	var result []TrustService
	for _, trustService := range trustServices {
		if trustServiceCheck.isAcceptable(&trustService) {
			result = append(result, trustService)
		}
	}
	return result
}

func (s *ServiceByCertificateTypeFilter) isAcceptable(trustService *TrustService) bool {
	issuance := s.certificate.GetNotBefore()
	if IsPostEIDAS(issuance) {
		aSIs := trustService.GetAdditionalServiceInfos()
		aSIESign := IsForESignatures(aSIs)
		aSIESeals := IsForESeals(aSIs)
		aSIWSA := IsForWebAuth(aSIs)

		qualifiers := trustService.GetQualifiers()
		qcForESign := IsQcForESig(qualifiers)
		qcForESeals := IsQcForESeal(qualifiers)
		qcForWSA := IsQcForWSA(qualifiers)

		qcForESign = qcForESign || (!qcForESeals && !qcForWSA && s.certificate.isQcCompliance())

		counter := 0
		for _, qcForXX := range []bool{qcForESign, qcForESeals, qcForWSA} {
			if qcForXX {
				counter++
			}
		}
		onlyOneQcForXX := counter == 1

		strategy := CreateTypeFromCert(s.certificate)
		certType := strategy.GetType()

		overruleForESign := aSIESign && qcForESign && onlyOneQcForXX
		overruleForESeals := aSIESeals && qcForESeals && onlyOneQcForXX
		overruleForWSA := aSIWSA && qcForWSA && onlyOneQcForXX

		switch certType {
		case CertTypeESign:
			return aSIESign || overruleForESeals || overruleForWSA
		case CertTypeESeal:
			return aSIESeals || overruleForESign || overruleForWSA
		case CertTypeWSA:
			return aSIWSA || overruleForESeals || overruleForESign
		case CertTypeUnknown:
			return true
		default:
			return true
		}
	}

	return true
}

func (s *ServiceByDateFilter) isAcceptable(trustService *TrustService) bool {
	if s.date.IsZero() {
		return false
	}
	startDate := trustService.GetStartDate()
	endDate := trustService.GetEndDate()
	return (!startDate.IsZero() &&
		(s.date.After(*startDate) || s.date.Equal(*startDate))) &&
		(endDate.IsZero() ||
			(s.date.Before(*endDate) || s.date.Equal(*endDate)))
}

func (s *GrantedServiceFilter) isAcceptable(trustService *TrustService) bool {
	startDate := trustService.GetStartDate()
	if IsPostEIDAS(*startDate) {
		return isAcceptableStatusAfterEIDAS(trustService.GetStatus())
	} else {
		return isAcceptableStatusBeforeEIDAS(trustService.GetStatus())
	}
}

func (s *CaQcServiceFilter) isAcceptable(trustService *TrustService) bool {
	return isCaQc(trustService.GetType())
}

func (s *ServiceConsistencyFilter) isAcceptable(trustService *TrustService) bool {
	return (&TrustServiceConsistencyChecker{}).IsConsistent(trustService)
}

func (s *ServiceByTLUrlFilter) isAcceptable(trustService *TrustService) bool {
	for _, tlUrl := range s.tlUrls {
		if strings.EqualFold(tlUrl, trustService.GetTrustedList().GetUrl()) {
			return true
		}
	}
	return false
}
