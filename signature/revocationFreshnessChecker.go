package signature

import (
	"errors"
	"time"
)

type RFCBase struct {
	revocationData *RevocationWrapper
}

func (c *RFCBase) getFailedIndicationForConclusion() *Indication {
	return &IndicationIndeterminate
}

func (c *RFCBase) getFailedSubIndicationForConclusion() *SubIndication {
	return &SubIndicationTryLater
}

type RevocationFreshnessChecker struct {
	validationPolicy ValidationPolicy
	sigWrapper       *SignatureWrapper
	revocationData   *RevocationWrapper
	validationDate   *time.Time
}

type NextUpdateCheck struct {
	*RFCBase
}

type RV interface {
	process(bool) bool
	getMaxFreshness() int64
}

type RevocationFreshCheck struct {
	*RFCBase
	revocationDataFreshCheck RV
	validationDate           *time.Time
}

type RevocationDataFreshCheck struct {
	revocationData *RevocationWrapper
	constraint     *TimeConstraint
}

type RevocationDataFreshCheckWithNullConstraint struct {
	revocationData *RevocationWrapper
}

func (rfc *RevocationFreshnessChecker) Execute() (*RFCConstraintsConclusion, error) {
	if rfc.revocationData != nil {
		revocationFreshnessConstraint := rfc.validationPolicy.GetRevocationFreshnessConstraint()
		var firstItem *ChainItem
		if revocationFreshnessConstraint == nil || LevelIgnore == *revocationFreshnessConstraint.GetLevel() {
			switch rfc.revocationData.GetRevocationType() {
			case RevocationTypeCRL:
				firstItem = rfc.crlNextUpdateCheck()
				break
			case RevocationTypeOCSP:
				firstItem = rfc.ocspNextUpdateCheck()
				break
			default:
				return nil, errors.New("invalid revocation type")
			}
		}

		revocationDataFreshCheck := rfc.revocationDataFreshCheck(revocationFreshnessConstraint)
		if firstItem == nil {
			firstItem = revocationDataFreshCheck
		} else {
			firstItem.SetNextItem(revocationDataFreshCheck)
		}
	}

	return &RFCConstraintsConclusion{}, nil
}

func (rfc *RevocationFreshnessChecker) crlNextUpdateCheck() *ChainItem {
	return &ChainItem{
		constraint: rfc.validationPolicy.GetCRLNextUpdatePresentConstraint(),
		current:    &NextUpdateCheck{&RFCBase{rfc.revocationData}}}
}

func (rfc *RevocationFreshnessChecker) ocspNextUpdateCheck() *ChainItem {
	return &ChainItem{
		constraint: rfc.validationPolicy.GetOCSPNextUpdatePresentConstraint(),
		current:    &NextUpdateCheck{&RFCBase{rfc.revocationData}}}
}

func (rfc *RevocationFreshnessChecker) revocationDataFreshCheck(revocationFreshnessConstraint *TimeConstraint) *ChainItem {
	if revocationFreshnessConstraint != nil {
		return &ChainItem{
			constraint: revocationFreshnessConstraint,
			current: &RevocationFreshCheck{
				&RFCBase{rfc.revocationData},
				&RevocationDataFreshCheck{rfc.revocationData, revocationFreshnessConstraint},
				rfc.validationDate}}
	} else {
		constraint := rfc.validationPolicy.GetRevocationFreshnessNextUpdateConstraint()
		return &ChainItem{
			constraint: constraint,
			current: &RevocationFreshCheck{
				&RFCBase{rfc.revocationData},
				&RevocationDataFreshCheckWithNullConstraint{rfc.revocationData},
				rfc.validationDate}}
	}
}

func (rfc *RevocationFreshnessChecker) cryptographicCheck() *ChainItem {
	return &ChainItem{
		constraint: rfc.validationPolicy.GetSignatureCryptographicConstraint(),
		a}
}

func (n *NextUpdateCheck) process() bool {
	if n.revocationData != nil {
		return n.revocationData.GetNextUpdate() != nil
	}
	return false
}

func (r *RevocationFreshCheck) isThisUpdateTimeAfterValidationTime() bool {
	limit := r.validationDate.UnixMilli() - r.revocationDataFreshCheck.getMaxFreshness()
	return r.revocationData.GetThisUpdate() != nil && r.revocationData.GetThisUpdate().After(time.UnixMilli(limit))
}

func (r *RevocationFreshCheck) process() bool {
	return r.revocationDataFreshCheck.process(r.isThisUpdateTimeAfterValidationTime())
}

func (r *RevocationDataFreshCheck) process(isThisUpdateTimeAfterValidationTime bool) bool {
	if r.revocationData != nil {
		return isThisUpdateTimeAfterValidationTime
	}
	return false
}

func (r *RevocationDataFreshCheck) getMaxFreshness() int64 {
	return convertDuration(r.constraint)
}

func (r *RevocationDataFreshCheckWithNullConstraint) process(isThisUpdateTimeAfterValidationTime bool) bool {
	if r.revocationData != nil && r.revocationData.GetNextUpdate() != nil {
		return isThisUpdateTimeAfterValidationTime
	}
	return false
}

func (r *RevocationDataFreshCheckWithNullConstraint) getMaxFreshness() int64 {
	return diff(r.revocationData.GetNextUpdate(), r.revocationData.GetThisUpdate())
}

func convertDuration(timeConstraint *TimeConstraint) int64 {
	return 0
}

func diff(nextUpdate *time.Time, thisUpdate *time.Time) int64 {
	var nextUpdateTime int64
	if nextUpdate == nil {
		nextUpdateTime = 0
	} else {
		nextUpdateTime = nextUpdate.UnixMilli()
	}

	var thisUpdateTime int64
	if thisUpdate == nil {
		thisUpdateTime = 0
	} else {
		thisUpdateTime = thisUpdate.UnixMilli()
	}
	return nextUpdateTime - thisUpdateTime
}
