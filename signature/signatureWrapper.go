package signature

import "jades/certificate"

type SignatureWrapper struct {
}

func (sw *SignatureWrapper) GetSignatureFormat() SigLevel {
	return SigLevelJAdESBaselineT
}

func (sw *SignatureWrapper) IsSignatureDuplicated() bool {
	return false
}

func (sw *SignatureWrapper) GetSigningCertificate() *certificate.CertificateWrapper {
	return nil
}

func (sw *SignatureWrapper) GetSigningCertificateReferences() []certificate.CertificateRefWrapper {
	return nil
}

func (sw *SignatureWrapper) GetSigningCertificateReference() *certificate.CertificateRefWrapper {
	return nil
}

func (sw *SignatureWrapper) GetPolicyId() string {
	return ""
}

func (sw *SignatureWrapper) GetDigestMatchers() []DigestMatcher {
	return nil
}

func (sw *SignatureWrapper) GetSignatureScopes() []SigScope {
	return nil
}

func (sw *SignatureWrapper) GetEncryptionAlgorithm() *EncryptionAlgorithm {
	return nil
}

func (sw *SignatureWrapper) GetDigestAlgorithm() *DigestAlgorithm {
	return nil
}

func (sw *SignatureWrapper) GetKeyLengthUsedToSignThisToken() *string {
	result := ""
	return &result
}

func (sw *SignatureWrapper) IsSigningCertificateReferencePresent() bool {
	return false
}

func (sw *SignatureWrapper) IsPolicyPresent() bool {
	return false
}

func (sw *SignatureWrapper) IsPolicyIdentified() bool {
	return false
}

func (sw *SignatureWrapper) IsPolicyStorePresent() bool {
	return false
}

func (sw *SignatureWrapper) IsPolicyZeroHash() bool {
	return false
}

func (sw *SignatureWrapper) IsPolicyDigestValid() bool {
	return false
}
