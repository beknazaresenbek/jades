package signature

type Indication struct {
	uri string
}

type SubIndication struct {
	uri string
}

var (
	IndicationPassed        = Indication{uri: "urn:etsi:019102:mainindication:passed"}
	IndicationFailed        = Indication{uri: "urn:etsi:019102:mainindication:failed"}
	IndicationIndeterminate = Indication{uri: "urn:etsi:019102:mainindication:indeterminate"}
)

var (
	SubIndicationFormatFailure             = SubIndication{uri: "urn:etsi:019102:subindication:FORMAT_FAILURE"}
	SubIndicationNoSigningCertificateFound = SubIndication{uri: "urn:etsi:019102:subindication:NO_SIGNING_CERTIFICATE_FOUND"}
	SubIndicationPolicyProcessingError     = SubIndication{uri: "urn:etsi:019102:subindication:POLICY_PROCESSING_ERROR"}
	SubIndicationPolicyNotAvailable        = SubIndication{uri: "urn:etsi:019102:subindication:SIGNATURE_POLICY_NOT_AVAILABLE"}
	SubIndicationTryLater                  = SubIndication{uri: "urn:etsi:019102:subindication:TRY_LATER"}
	SubIndicationNoCertificateChainFound   = SubIndication{uri: "urn:etsi:019102:subindication:NO_CERTIFICATE_CHAIN_FOUND"}
)

type Conclusion struct {
	indication    *Indication
	subIndication *SubIndication
}

func (c *Conclusion) GetIndication() *Indication {
	return c.indication
}

func (c *Conclusion) GetSubIndication() *SubIndication {
	return c.subIndication
}

func (c *Conclusion) SetIndication(indication *Indication) {
	c.indication = indication
}

func (c *Conclusion) SetSubIndication(subIndication *SubIndication) {
	c.subIndication = subIndication
}

type Constraint struct {
}

type ConstraintsConclusion struct {
	constraint []Constraint
	conclusion *Conclusion
	title      string
}

func (cc *ConstraintsConclusion) GetConclusion() *Conclusion {
	return cc.conclusion
}

func (cc *ConstraintsConclusion) SetConclusion(conclusion *Conclusion) {
	cc.conclusion = conclusion
}

func (cc *ConstraintsConclusion) GetTitle() string {
	return cc.title
}

func (cc *ConstraintsConclusion) SetTitle(title string) {
	cc.title = title
}

func (cc *ConstraintsConclusion) GetConstraint() []Constraint {
	return cc.constraint
}

type FCConstraintsConclusion struct {
	*ConstraintsConclusion
}

type ISCConstraintsConclusion struct {
	*ConstraintsConclusion
	certificateChain string
}

func (isc *ISCConstraintsConclusion) GetCertificateChain() string {
	return isc.certificateChain
}

type VCIConstraintsConclusion struct {
	*ConstraintsConclusion
}

type XCVConstraintsConclusion struct {
	*ConstraintsConclusion
	subXCV []string
}

type CVConstraintsConclusion struct {
	*ConstraintsConclusion
}

type SAVConstraintsConclusion struct {
	*ConstraintsConclusion
	cryptographicValidation string
}

func (svc *SAVConstraintsConclusion) GetCryptographicValidation() string {
	return svc.cryptographicValidation
}

type RFCConstraintsConclusion struct {
	*ConstraintsConclusion
	id string
}
