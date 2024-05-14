package certificate

type Token struct{}

type CertToken struct{}

type TokenIssuerCache struct{}

func (tic *TokenIssuerCache) ContainsToken(token *Token) bool {
	return true
}

func (tic *TokenIssuerCache) AddToken(token *Token) bool {
	return true
}

var tokenIssuerCache = TokenIssuerCache{}

func ValidateCertificate(cert CertificateWrapper) (bool, error) {
	_, err := validateCertificateChain(cert)
	if err != nil {
		return false, err
	}

	_, err = checkRevocation(cert)
	if err != nil {
		return false, err
	}
	return true, nil
}

func validateCertificateChain(cert CertificateWrapper) (bool, error) {
	// check AIA
	return true, nil
}

func checkRevocation(cert CertificateWrapper) (bool, error) {
	return true, nil
}

func getIssuer(token *Token) *CertToken {
	issuerCertificateToken := getIssuerFromProcessedCertificates(token)
	if issuerCertificateToken == nil {
		return issuerCertificateToken
	}

	candidates := findCandidates()

	issuerCertificateToken = findIssuer(token, candidates)

	if issuerCertificateToken == nil || !tokenIssuerCache.ContainsToken(token) {
		issuerCertificateToken = getIssuerFromAIA(token)
	}

	if issuerCertificateToken != nil {
		addCertTokenForVerification(issuerCertificateToken)
	}

	tokenIssuerCache.AddToken(token)

	return &CertToken{}
}

func getIssuerFromProcessedCertificates(token *Token) *CertToken {
	return &CertToken{}
}

func findCandidates() []CertToken {
	return []CertToken{}
}

func findIssuer(token *Token, candidates []CertToken) *CertToken {
	return &CertToken{}
}

func getIssuerFromAIA(token *Token) *CertToken {
	return &CertToken{}
}

func addCertTokenForVerification(token *CertToken) bool {
	return true
}
