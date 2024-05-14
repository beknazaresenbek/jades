package signature

type FCBase struct {
	signatureWrapper *SignatureWrapper
}

func (c *FCBase) getFailedIndicationForConclusion() *Indication {
	return &IndicationFailed
}

func (c *FCBase) getFailedSubIndicationForConclusion() *SubIndication {
	return &SubIndicationFormatFailure
}

type SignatureFormatChecking struct {
	validationPolicy      ValidationPolicy
	signatureWrapper      *SignatureWrapper
	constraintsConclusion *FCConstraintsConclusion
	fCBase                *FCBase
}

type FormatCheck struct {
	*FCBase
	acceptedFormats []string
}

type DuplicateCheck struct {
	*FCBase
}

type ReferenceDuplicateCheck struct {
	*FCBase
}

type FullScopeCheck struct {
	*FCBase
}

type EllipticCurveKeySizeCheck struct {
	*FCBase
}

func (s *SignatureFormatChecking) Execute() *FCConstraintsConclusion {
	s.fCBase = &FCBase{s.signatureWrapper}

	formatCheck := s.formatCheck()
	duplicateCheck := s.signatureDuplicateCheck()
	refDuplicateCheck := s.referenceDuplicateCheck()
	fullScopeCheck := s.fullScopeCheck()

	formatCheck.SetNextItem(duplicateCheck)
	duplicateCheck.SetNextItem(refDuplicateCheck)
	refDuplicateCheck.SetNextItem(fullScopeCheck)

	if SigFormJAdES == s.signatureWrapper.GetSignatureFormat().GetSigForm() {
		if s.signatureWrapper.GetEncryptionAlgorithm() != nil && s.signatureWrapper.GetEncryptionAlgorithm().IsEquivalent(EncryptionAlgorithmECDSA) {
			ellipticCurveKeySizeCheck := s.ellipticCurveKeySizeCheck()
			formatCheck.SetNextItem(ellipticCurveKeySizeCheck)
		}
	}

	formatCheck.Execute()

	return s.constraintsConclusion
}

func (s *SignatureFormatChecking) formatCheck() *ChainItem {
	constraint := s.validationPolicy.GetSignatureFormatConstraint()
	return &ChainItem{
		constraint: constraint,
		current:    &FormatCheck{FCBase: s.fCBase, acceptedFormats: constraint.GetId()}}
}

func (s *SignatureFormatChecking) signatureDuplicateCheck() *ChainItem {
	return &ChainItem{
		constraint: s.validationPolicy.GetSignatureDuplicatedConstraint(),
		current:    &DuplicateCheck{s.fCBase}}
}

func (s *SignatureFormatChecking) referenceDuplicateCheck() *ChainItem {
	return &ChainItem{
		constraint: &BaseConstraint{LevelFail},
		current:    &ReferenceDuplicateCheck{s.fCBase}}
}

func (s *SignatureFormatChecking) fullScopeCheck() *ChainItem {
	return &ChainItem{
		constraint: s.validationPolicy.GetFullScopeConstraint(),
		current:    &FullScopeCheck{s.fCBase}}
}

func (s *SignatureFormatChecking) ellipticCurveKeySizeCheck() *ChainItem {
	return &ChainItem{
		constraint: s.validationPolicy.GetEllipticCurveKeySizeConstraint(),
		current:    &EllipticCurveKeySizeCheck{s.fCBase}}
}

func (c *FormatCheck) process() bool {
	constraintChecker := MultiValuesConstraintChecker{}
	return constraintChecker.check(c.acceptedFormats, string(c.signatureWrapper.GetSignatureFormat()))
}

func (c *DuplicateCheck) process() bool {
	return !c.signatureWrapper.IsSignatureDuplicated()
}

func (c *ReferenceDuplicateCheck) process() bool {
	for _, matcher := range c.signatureWrapper.GetDigestMatchers() {
		if matcher.IsDuplicated() {
			return false
		}
	}
	return true
}

func (c *FullScopeCheck) process() bool {
	for _, sigScope := range c.signatureWrapper.GetSignatureScopes() {
		if SigScopeTypeFull != sigScope.GetScope() {
			return false
		}
	}
	return true
}

func (c *EllipticCurveKeySizeCheck) process() bool {
	if c.signatureWrapper.GetEncryptionAlgorithm() == nil ||
		c.signatureWrapper.GetDigestAlgorithm() == nil ||
		c.signatureWrapper.GetKeyLengthUsedToSignThisToken() == nil {
		return false
	}
	return !c.signatureWrapper.GetEncryptionAlgorithm().IsEquivalent(EncryptionAlgorithmECDSA) ||
		c.isDigestAlgorithmAuthorized() && c.keySizeCorrespondsDigestAlgorithm()
}

func (c *EllipticCurveKeySizeCheck) isDigestAlgorithmAuthorized() bool {
	switch c.signatureWrapper.GetDigestAlgorithm().GetName() {
	case DigestAlgorithmSHA256.GetName():
	case DigestAlgorithmSHA384.GetName():
	case DigestAlgorithmSHA512.GetName():
		return true
	}
	return false
}

func (c *EllipticCurveKeySizeCheck) keySizeCorrespondsDigestAlgorithm() bool {
	correspondingKeySize := c.getCorrespondingKeySize(c.signatureWrapper.GetDigestAlgorithm())
	return correspondingKeySize == *c.signatureWrapper.GetKeyLengthUsedToSignThisToken()
}

func (c *EllipticCurveKeySizeCheck) getCorrespondingKeySize(digestAlgorithm *DigestAlgorithm) string {
	switch digestAlgorithm.GetName() {
	case DigestAlgorithmSHA256.GetName():
		return "256"
	case DigestAlgorithmSHA384.GetName():
		return "384"
	case DigestAlgorithmSHA512.GetName():
		return "512"
	}
	return ""
}
