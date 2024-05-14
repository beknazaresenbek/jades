package signature

type ISCBase struct {
	signatureWrapper *SignatureWrapper
}

func (c *ISCBase) getFailedIndicationForConclusion() *Indication {
	return &IndicationIndeterminate
}

func (c *ISCBase) getFailedSubIndicationForConclusion() *SubIndication {
	return &SubIndicationNoSigningCertificateFound
}

type IdentificationOfTheSigningCertificate struct {
	validationPolicy      ValidationPolicy
	sigWrapper            *SignatureWrapper
	constraintsConclusion *ISCConstraintsConclusion
	iSCBase               *ISCBase
}

func (id *IdentificationOfTheSigningCertificate) Execute() *ISCConstraintsConclusion {
	id.iSCBase = &ISCBase{id.sigWrapper}

	certRecognitionCheck := id.signingCertificateRecognition()

	if id.sigWrapper.IsSigningCertificateReferencePresent() {
		digestValuePresentCheck := id.digestValuePresent()
		digestValueMatchCheck := id.digestValueMatch()
		certRecognitionCheck.SetNextItem(digestValuePresentCheck)
		digestValuePresentCheck.SetNextItem(digestValueMatchCheck)

		if id.sigWrapper.GetSigningCertificateReference() != nil &&
			id.sigWrapper.GetSigningCertificateReference().IsIssuerSerialPresent() {
			issuerSerialMatchCheck := id.issuerSerialMatch()
			digestValueMatchCheck.SetNextItem(issuerSerialMatchCheck)
		}
	}

	certRecognitionCheck.Execute()

	return id.constraintsConclusion
}

func (id *IdentificationOfTheSigningCertificate) signingCertificateRecognition() *ChainItem {
	return &ChainItem{
		constraint: id.validationPolicy.GetSigningCertificateRecognitionConstraint(),
		current:    &SigningCertificateRecognitionCheck{id.iSCBase}}
}

func (id *IdentificationOfTheSigningCertificate) digestValuePresent() *ChainItem {
	return &ChainItem{
		constraint: id.validationPolicy.GetSigningCertificateDigestValuePresentConstraint(),
		current:    &DigestValuePresentCheck{id.iSCBase}}
}

func (id *IdentificationOfTheSigningCertificate) digestValueMatch() *ChainItem {
	return &ChainItem{
		constraint: id.validationPolicy.GetSigningCertificateDigestValueMatchConstraint(),
		current:    &DigestValueMatchCheck{id.iSCBase}}
}

func (id *IdentificationOfTheSigningCertificate) issuerSerialMatch() *ChainItem {
	return &ChainItem{
		constraint: id.validationPolicy.GetSigningCertificateIssuerSerialMatchConstraint(),
		current:    &IssuerSerialMatchCheck{id.iSCBase}}
}

type SigningCertificateRecognitionCheck struct {
	*ISCBase
}

type DigestValuePresentCheck struct {
	*ISCBase
}

type DigestValueMatchCheck struct {
	*ISCBase
}

type IssuerSerialMatchCheck struct {
	*ISCBase
}

func (c *SigningCertificateRecognitionCheck) process() bool {
	return c.signatureWrapper.GetSigningCertificate() != nil
}

func (c *DigestValuePresentCheck) process() bool {
	signingCertificateReferences := c.signatureWrapper.GetSigningCertificateReferences()
	if signingCertificateReferences != nil {
		for _, reference := range signingCertificateReferences {
			if reference.IsDigestValuePresent() {
				return true
			}
		}
	}
	return false
}

func (c *DigestValueMatchCheck) process() bool {
	signingCertificateReferences := c.signatureWrapper.GetSigningCertificateReferences()
	if signingCertificateReferences != nil {
		for _, reference := range signingCertificateReferences {
			if reference.IsDigestValuePresent() && reference.IsDigestValueMatch() {
				return true
			}
		}
	}
	return false
}

func (c *IssuerSerialMatchCheck) process() bool {
	signingCertificateReference := c.signatureWrapper.GetSigningCertificateReference()
	if signingCertificateReference != nil {
		return signingCertificateReference.IsIssuerSerialMatch()
	} else {
		return false
	}
}
