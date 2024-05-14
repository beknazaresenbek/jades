package certificate

import "time"

type TrustService struct {
	trustedList            TrustedList
	lotl                   TrustedList
	trustServiceType       string
	status                 string
	startDate              time.Time
	endDate                time.Time
	TSPNames               []string
	TSPTradeNames          []string
	additionalServiceInfos []AdditionalServiceInformation
	qualifiers             []ServiceQualification
}

func (ts *TrustService) GetQualifiers() []ServiceQualification {
	return ts.qualifiers
}

func (ts *TrustService) GetAdditionalServiceInfos() []AdditionalServiceInformation {
	return ts.additionalServiceInfos
}

func (ts *TrustService) GetTrustedList() *TrustedList {
	return &ts.trustedList
}

func (ts *TrustService) GetLOTL() *TrustedList {
	return &ts.lotl
}

func (ts *TrustService) GetType() string {
	return ts.trustServiceType
}

func (ts *TrustService) GetStatus() string {
	return ts.status
}

func (ts *TrustService) GetStartDate() *time.Time {
	return &ts.startDate
}

func (ts *TrustService) GetEndDate() *time.Time {
	return &ts.endDate
}

func GetAcceptableTLUrls(trustServices []TrustService) []string {
	return []string{}
}
