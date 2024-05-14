package signature

import (
	"jades/certificate"
	"time"
)

type XCVBase struct {
	certificate *certificate.CertificateWrapper
}

func (c *XCVBase) getFailedIndicationForConclusion() *Indication {
	return &IndicationIndeterminate
}

func (c *XCVBase) getFailedSubIndicationForConclusion() *SubIndication {
	return &SubIndicationNoCertificateChainFound
}

type X509CertificateValidation struct {
	validationPolicy ValidationPolicy
	certificate      *certificate.CertificateWrapper
}

type ProspectiveCertificateChainCheck struct {
	*XCVBase
}

type TrustServiceTypeIdentifierCheck struct {
	*XCVBase
	usageTime                   *time.Time
	trustServiceTypeIdentifiers []string
}

type TrustServiceStatusCheck struct {
	*XCVBase
	usageTime          *time.Time
	trustServiceStatus []string
}

func (c *X509CertificateValidation) Execute() *XCVConstraintsConclusion {
	firstItem := c.prospectiveCertificateChain()
	if c.certificate.IsTrusted() || c.certificate.IsTrustedChain() || !c.prospectiveCertificateChainCheckEnforced() {
		trustServiceWithExpectedTypeIdentifier := c.trustServiceWithExpectedTypeIdentifier()
		trustServiceWithExpectedStatus := c.trustServiceWithExpectedStatus()

		firstItem.SetNextItem(trustServiceWithExpectedTypeIdentifier)
		trustServiceWithExpectedTypeIdentifier.SetNextItem(trustServiceWithExpectedStatus)
	}
	return nil
}

func (c *X509CertificateValidation) prospectiveCertificateChain() *ChainItem {
	return &ChainItem{
		constraint: c.validationPolicy.GetProspectiveCertificateChainConstraint(),
		current:    &ProspectiveCertificateChainCheck{&XCVBase{c.certificate}}}
}

func (c *X509CertificateValidation) prospectiveCertificateChainCheckEnforced() bool {
	constraint := c.validationPolicy.GetProspectiveCertificateChainConstraint()
	return constraint != nil && LevelFail == *constraint.GetLevel()
}

func (c *X509CertificateValidation) trustServiceWithExpectedTypeIdentifier() *ChainItem {
	constraint := c.validationPolicy.GetTrustServiceTypeIdentifierConstraint()
	usageTime := time.Now()
	return &ChainItem{
		constraint: constraint,
		current: &TrustServiceTypeIdentifierCheck{
			&XCVBase{c.certificate},
			&usageTime,
			constraint.GetId()}}
}

func (c *X509CertificateValidation) trustServiceWithExpectedStatus() *ChainItem {
	constraint := c.validationPolicy.GetTrustServiceStatusConstraint()
	usageTime := time.Now()
	return &ChainItem{
		constraint: constraint,
		current: &TrustServiceStatusCheck{
			&XCVBase{c.certificate},
			&usageTime,
			constraint.GetId()}}
}

func (c *ProspectiveCertificateChainCheck) process() bool {
	return c.certificate.IsTrusted() || c.certificate.IsTrustedChain()
}

func (c *TrustServiceTypeIdentifierCheck) process() bool {
	if c.certificate.IsCertificateChainFromTrustedStore() {
		return true
	}

	trustServices := c.certificate.GetTrustServices()
	constraintChecker := MultiValuesConstraintChecker{}
	for _, trustService := range trustServices {
		if constraintChecker.check(c.trustServiceTypeIdentifiers, trustService.GetType()) &&
			trustService.GetStartDate() != nil {
			if c.usageTime.Compare(*trustService.GetStartDate()) >= 0 &&
				(trustService.GetEndDate() == nil || c.usageTime.Before(*trustService.GetEndDate())) {
				return true
			}
		}
	}
	return false
}

func (c *TrustServiceStatusCheck) process() bool {
	if c.certificate.IsCertificateChainFromTrustedStore() {
		return true
	}

	trustServices := c.certificate.GetTrustServices()
	constraintChecker := MultiValuesConstraintChecker{}
	for _, trustService := range trustServices {
		if constraintChecker.check(c.trustServiceStatus, trustService.GetStatus()) &&
			trustService.GetStartDate() != nil {
			if c.usageTime.Compare(*trustService.GetStartDate()) >= 0 &&
				(trustService.GetEndDate() == nil || c.usageTime.Before(*trustService.GetEndDate())) {
				return true
			}
		}
	}
	return false
}
