package signature

import "jades/certificate"

type Qualification struct {
	readable string
	label    string
	uri      string
}

type Validation struct{}

var (
	QESig = Qualification{"QESig", "Qualified Electronic Signature", "urn:cef:dss:signatureQualification:QESig"}
)

func GetSignatureQualification(validation *Validation) *Qualification {
	return &QESig
}

func ExecuteSignatureValidation() *Validation {
	return &Validation{}
}

func HasValidQualifiedElectronicSignature(certWrapper *certificate.CertificateWrapper) *Qualification {
	certQualificationCalculator := certificate.QualificationCalculator{Certificate: certWrapper}

	certQualificationAtIssuanceTime := certQualificationCalculator.GetQualification(
		certWrapper.TrustServiceFinder.FindCatching(certWrapper, certificate.VTCertificateIssuanceTime))

	certQualificationAtSigningTime := certQualificationCalculator.GetQualification(
		certWrapper.TrustServiceFinder.FindCatching(certWrapper, certificate.VTValidationTime))

	(&certificate.FinalQualificationCalculator{
		CertQualificationAtIssuanceTime: &certQualificationAtIssuanceTime,
		CertQualificationAtSigningTime:  &certQualificationAtSigningTime}).GetFinalQualification()

	return GetSignatureQualification(ExecuteSignatureValidation())
}
