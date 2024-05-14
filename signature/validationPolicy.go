package signature

type ValidationModel string

const (
	ValidationModelShell ValidationModel = "SHELL"
	ValidationModelChain ValidationModel = "CHAIN"
)

type ValidationPolicy interface {
	GetSignatureFormatConstraint() *MultiValuesConstraint
	GetSignatureDuplicatedConstraint() *BaseConstraint
	GetSigningCertificateRecognitionConstraint() *BaseConstraint
	GetSigningCertificateDigestValuePresentConstraint() *BaseConstraint
	GetSigningCertificateDigestValueMatchConstraint() *BaseConstraint
	GetSigningCertificateIssuerSerialMatchConstraint() *BaseConstraint
	GetSignaturePolicyConstraint() *MultiValuesConstraint
	GetSignaturePolicyIdentifiedConstraint() *BaseConstraint
	GetSignaturePolicyStorePresentConstraint() *BaseConstraint
	GetSignaturePolicyPolicyHashValid() *BaseConstraint
	GetProspectiveCertificateChainConstraint() *BaseConstraint
	GetFullScopeConstraint() *BaseConstraint
	GetEllipticCurveKeySizeConstraint() *BaseConstraint
	GetRevocationFreshnessConstraint() *TimeConstraint
	GetCRLNextUpdatePresentConstraint() *BaseConstraint
	GetOCSPNextUpdatePresentConstraint() *BaseConstraint
	GetRevocationFreshnessNextUpdateConstraint() *BaseConstraint
	GetSignatureCryptographicConstraint() *CryptographicConstraint
	GetTrustServiceTypeIdentifierConstraint() *MultiValuesConstraint
	GetTrustServiceStatusConstraint() *MultiValuesConstraint
	GetValidationModel() ValidationModel
}
