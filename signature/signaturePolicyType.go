package signature

type SignaturePolicyType string

const (
	SignaturePolicyTypeNoPolicy       SignaturePolicyType = "NO_POLICY"
	SignaturePolicyTypeAnyPolicy      SignaturePolicyType = "ANY_POLICY"
	SignaturePolicyTypeImplicitPolicy SignaturePolicyType = "IMPLICIT_POLICY"
)
