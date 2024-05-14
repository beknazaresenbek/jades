package signature

import "slices"

type VCIBase struct {
	signatureWrapper *SignatureWrapper
	subIndication    *SubIndication
}

func (c *VCIBase) getFailedIndicationForConclusion() *Indication {
	return &IndicationIndeterminate
}

func (c *VCIBase) getFailedSubIndicationForConclusion() *SubIndication {
	return c.subIndication
}

type ValidationContextInitialization struct {
	validationPolicy      ValidationPolicy
	sigWrapper            *SignatureWrapper
	constraintsConclusion *ISCConstraintsConclusion
}

type SignaturePolicyIdentifierCheck struct {
	*VCIBase
	acceptablePolicies []string
}

type SignaturePolicyIdentifiedCheck struct {
	*VCIBase
}

type SignaturePolicyStoreCheck struct {
	*VCIBase
}

type SignaturePolicyHashValidCheck struct {
	*VCIBase
}

type SignaturePolicyZeroHashCheck struct {
	*VCIBase
}

func (vci *ValidationContextInitialization) Execute() *VCIConstraintsConclusion {
	signaturePolicyIdentifier := vci.signaturePolicyIdentifier()

	if vci.sigWrapper.IsPolicyPresent() && string(SignaturePolicyTypeImplicitPolicy) != vci.sigWrapper.GetPolicyId() {
		signaturePolicyIdentified := vci.signaturePolicyIdentified()
		signaturePolicyStorePresent := vci.signaturePolicyStorePresent()

		signaturePolicyIdentifier.SetNextItem(signaturePolicyIdentified)
		signaturePolicyIdentified.SetNextItem(signaturePolicyStorePresent)

		if vci.sigWrapper.IsPolicyIdentified() {
			if vci.sigWrapper.IsPolicyZeroHash() {
				signaturePolicyStorePresent.SetNextItem(vci.signaturePolicyZeroHash())
			} else {
				signaturePolicyStorePresent.SetNextItem(vci.signaturePolicyHashValid())
			}
		}
	}

	signaturePolicyIdentifier.Execute()

	return &VCIConstraintsConclusion{}
}

func (vci *ValidationContextInitialization) signaturePolicyIdentifier() *ChainItem {
	constraint := vci.validationPolicy.GetSignaturePolicyConstraint()
	return &ChainItem{
		constraint: constraint,
		current: &SignaturePolicyIdentifierCheck{
			&VCIBase{vci.sigWrapper, &SubIndicationPolicyProcessingError},
			constraint.GetId()}}
}

func (vci *ValidationContextInitialization) signaturePolicyIdentified() *ChainItem {
	return &ChainItem{
		constraint: vci.validationPolicy.GetSignaturePolicyIdentifiedConstraint(),
		current: &SignaturePolicyIdentifiedCheck{
			&VCIBase{vci.sigWrapper, &SubIndicationPolicyNotAvailable}}}
}

func (vci *ValidationContextInitialization) signaturePolicyStorePresent() *ChainItem {
	return &ChainItem{
		constraint: vci.validationPolicy.GetSignaturePolicyStorePresentConstraint(),
		current: &SignaturePolicyStoreCheck{
			&VCIBase{vci.sigWrapper, &SubIndicationPolicyNotAvailable}}}
}

func (vci *ValidationContextInitialization) signaturePolicyHashValid() *ChainItem {
	return &ChainItem{
		constraint: vci.validationPolicy.GetSignaturePolicyPolicyHashValid(),
		current: &SignaturePolicyHashValidCheck{
			&VCIBase{vci.sigWrapper, &SubIndicationPolicyProcessingError}}}
}

func (vci *ValidationContextInitialization) signaturePolicyZeroHash() *ChainItem {
	return &ChainItem{
		constraint: &BaseConstraint{LevelWarn},
		current: &SignaturePolicyZeroHashCheck{
			&VCIBase{vci.sigWrapper, &SubIndicationPolicyProcessingError}}}
}

func (s *SignaturePolicyIdentifierCheck) process() bool {
	if slices.Contains(s.acceptablePolicies, string(SignaturePolicyTypeNoPolicy)) && s.signatureWrapper.GetPolicyId() == "" ||
		slices.Contains(s.acceptablePolicies, string(SignaturePolicyTypeAnyPolicy)) && s.signatureWrapper.GetPolicyId() != "" ||
		slices.Contains(s.acceptablePolicies, string(SignaturePolicyTypeImplicitPolicy)) &&
			string(SignaturePolicyTypeImplicitPolicy) == s.signatureWrapper.GetPolicyId() {
		return true
	}
	constraintChecker := MultiValuesConstraintChecker{}
	return constraintChecker.check(s.acceptablePolicies, s.signatureWrapper.GetPolicyId())
}

func (s *SignaturePolicyIdentifiedCheck) process() bool {
	return s.signatureWrapper.IsPolicyPresent() && s.signatureWrapper.IsPolicyIdentified()
}

func (s *SignaturePolicyStoreCheck) process() bool {
	return s.signatureWrapper.IsPolicyStorePresent()
}

func (s *SignaturePolicyHashValidCheck) process() bool {
	return s.signatureWrapper.IsPolicyPresent() && s.signatureWrapper.IsPolicyDigestValid()
}

func (s *SignaturePolicyZeroHashCheck) process() bool {
	return s.signatureWrapper.IsPolicyZeroHash()
}
