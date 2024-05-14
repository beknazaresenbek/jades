package signature

type ReferenceValidation struct {
}

type DigestMatcher struct {
}

func (d *DigestMatcher) IsDuplicated() bool {
	return false
}

type CertificateValidity struct {
}

type CandidatesForSigningCertificate struct {
}

func (c *CandidatesForSigningCertificate) GetTheCertificateValidity() *CertificateValidity {
	return &CertificateValidity{}
}

type AdvancedSignature interface {
	GetReferenceValidations() []ReferenceValidation
	GetDetachedContents() string
	GetCandidatesForSigningCertificate() *CandidatesForSigningCertificate
}

type JWS interface {
}

type JAdESSignature struct {
	jws        JWS
	isDetached bool
}

func GetDigestMatchers(signature AdvancedSignature) []DigestMatcher {
	return nil
}
