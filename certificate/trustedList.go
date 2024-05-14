package certificate

type TrustedList struct {
	url string
}

func (tl *TrustedList) GetUrl() string {
	return tl.url
}

func ValidateTLs(trustedLists []TrustedList) []TrustedList {
	return trustedLists
}
