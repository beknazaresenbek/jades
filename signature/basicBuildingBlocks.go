package signature

type BasicBuildingBlocksConclusion struct {
	fc         *FCConstraintsConclusion
	isc        *ISCConstraintsConclusion
	vci        *VCIConstraintsConclusion
	xcv        *XCVConstraintsConclusion
	cv         *CVConstraintsConclusion
	sav        *SAVConstraintsConclusion
	conclusion *Conclusion
}

func (bbbc *BasicBuildingBlocksConclusion) SetFC(fc *FCConstraintsConclusion) {
	bbbc.fc = fc
}

func (bbbc *BasicBuildingBlocksConclusion) SetISC(isc *ISCConstraintsConclusion) {
	bbbc.isc = isc
}

func (bbbc *BasicBuildingBlocksConclusion) SetVCI(vci *VCIConstraintsConclusion) {
	bbbc.vci = vci
}

func (bbbc *BasicBuildingBlocksConclusion) SetXCV(xcv *XCVConstraintsConclusion) {
	bbbc.xcv = xcv
}

func (bbbc *BasicBuildingBlocksConclusion) SetCV(vcv *CVConstraintsConclusion) {
	bbbc.cv = vcv
}

func (bbbc *BasicBuildingBlocksConclusion) SetSAV(sav *SAVConstraintsConclusion) {
	bbbc.sav = sav
}

func (bbbc *BasicBuildingBlocksConclusion) GetConclusion() *Conclusion {
	return bbbc.conclusion
}

func (bbbc *BasicBuildingBlocksConclusion) SetConclusion(conclusion *Conclusion) {
	bbbc.conclusion = conclusion
}

type BasicBuildingBlocks struct {
	validationPolicy ValidationPolicy
	sigWrapper       *SignatureWrapper
	bbbConclusion    *BasicBuildingBlocksConclusion
}

func (bbb *BasicBuildingBlocks) GetBBBConclusion() *BasicBuildingBlocksConclusion {
	return bbb.bbbConclusion
}

func (bbb *BasicBuildingBlocks) Execute() {

	// 5.2.2 Format Checking
	bbb.executeFormatChecking()

	// 5.2.3 Identification of the signing certificate
	bbb.executeIdentificationOfTheSigningCertificate()

	// 5.2.4 Validation context initialization (only for signature)
	bbb.executeValidationContextInitialization()

	// 5.2.5 Revocation freshness checker
	bbb.executeRevocationFreshnessChecker()

	// 5.2.6 X.509 certificate validation
	bbb.executeX509CertificateValidation()

	// 5.2.7 Cryptographic verification
	bbb.executeCryptographicVerification()

	// 5.2.8 Signature acceptance validation (SAV)
	bbb.executeSignatureAcceptanceValidation()
}

func (bbb *BasicBuildingBlocks) executeFormatChecking() {
	sigFormatChecking := SignatureFormatChecking{validationPolicy: bbb.validationPolicy, signatureWrapper: bbb.sigWrapper}
	fcConstraintsConclusion := sigFormatChecking.Execute()
	bbb.bbbConclusion.SetFC(fcConstraintsConclusion)
	bbb.updateConclusion(fcConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) executeIdentificationOfTheSigningCertificate() {
	identificationOfTheSigningCertificate := IdentificationOfTheSigningCertificate{validationPolicy: bbb.validationPolicy, sigWrapper: bbb.sigWrapper}
	iscConstraintsConclusion := identificationOfTheSigningCertificate.Execute()
	bbb.bbbConclusion.SetISC(iscConstraintsConclusion)
	bbb.updateConclusion(iscConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) executeValidationContextInitialization() {
	validationContextInitialization := ValidationContextInitialization{validationPolicy: bbb.validationPolicy, sigWrapper: bbb.sigWrapper}
	vciConstraintsConclusion := validationContextInitialization.Execute()
	bbb.bbbConclusion.SetVCI(vciConstraintsConclusion)
	bbb.updateConclusion(vciConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) executeRevocationFreshnessChecker() {
	revocationFreshnessChecker := RevocationFreshnessChecker{}
}

func (bbb *BasicBuildingBlocks) executeX509CertificateValidation() {
	x509CertificateValidation := X509CertificateValidation{}
	xcvConstraintsConclusion := x509CertificateValidation.Execute()
	bbb.bbbConclusion.SetXCV(xcvConstraintsConclusion)
	bbb.updateConclusion(xcvConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) executeCryptographicVerification() {
	cryptographicVerification := CryptographicVerification{}
	cvConstraintsConclusion := cryptographicVerification.Execute()
	bbb.bbbConclusion.SetCV(cvConstraintsConclusion)
	bbb.updateConclusion(cvConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) executeSignatureAcceptanceValidation() {
	sav := SignatureAcceptanceValidation{}
	savConstraintsConclusion := sav.Execute()
	bbb.bbbConclusion.SetSAV(savConstraintsConclusion)
	bbb.updateConclusion(savConstraintsConclusion)
}

func (bbb *BasicBuildingBlocks) updateConclusion(constraintsConclusion ConstraintsConclusion) {
	bbb.bbbConclusion.SetConclusion(constraintsConclusion.GetConclusion())
}
