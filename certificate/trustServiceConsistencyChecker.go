package certificate

import (
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
)

type TrustServiceConsistencyChecker struct{}

func (checker *TrustServiceConsistencyChecker) IsConsistent(trustService *TrustService) bool {
	qualifiers := trustService.GetQualifiers()

	// mutually exclusive
	if IsQcForLegalPerson(qualifiers) && IsQcForESig(qualifiers) {
		return false
	}

	// mutually exclusive
	if IsQCStatement(qualifiers) && IsNotQualified(qualifiers) {
		return false
	}

	// mutually exclusive
	qcForESig := IsQcForESig(qualifiers)
	qcForESeal := IsQcForESeal(qualifiers)
	qcForWSA := IsQcForWSA(qualifiers)
	isUsageConsistent := !(qcForESig && qcForESeal) && !(qcForESig && qcForWSA) && !(qcForESeal && qcForWSA)
	if !isUsageConsistent {
		return false
	}

	if IsQcNoQSCD(qualifiers) && (IsQcWithQSCD(qualifiers) || IsQcQSCDManagedOnBehalf(qualifiers) ||
		IsQcQSCDStatusAsInCert(qualifiers)) {
		return false
	}

	if IsQcQSCDStatusAsInCert(qualifiers) && (IsQcWithQSCD(qualifiers) || IsQcQSCDManagedOnBehalf(qualifiers)) {
		return false
	}

	if IsQcNoSSCD(qualifiers) && (IsQcWithSSCD(qualifiers) || IsQcSSCDManagedOnBehalf(qualifiers) ||
		IsQcSSCDStatusAsInCert(qualifiers)) {
		return false
	}

	if IsQcSSCDStatusAsInCert(qualifiers) && (IsQcWithSSCD(qualifiers) || IsQcSSCDManagedOnBehalf(qualifiers)) {
		return false
	}

	startDate := trustService.GetStartDate()
	if IsPostEIDAS(*startDate) {
		qualifiers := trustService.GetQualifiers()
		qcPreEIDAS := IsQcWithSSCD(qualifiers) || IsQcNoSSCD(qualifiers)
		qcPostEIDAS := IsQcWithQSCD(qualifiers) || IsQcNoQSCD(qualifiers)
		if qcPreEIDAS && !qcPostEIDAS {
			return false
		}
	}

	aSIs := trustService.GetAdditionalServiceInfos()
	if len(aSIs) >= 1 && !slices.Contains(aSIs, getCorrespondingASIForCurrentUsageQC(qualifiers)) {
		return false
	}

	startDate = trustService.GetStartDate()
	if !(IsPostEIDAS(*startDate) || trustService.GetStatus() != TSSGranted.uri && trustService.GetStatus() != TSSWithdrawn.uri) {
		return false
	}

	if !IsPostEIDAS(*startDate) {
		aSIs := trustService.GetAdditionalServiceInfos()
		if IsForeSealsOnly(aSIs) || IsForWebAuthOnly(aSIs) {
			return false
		}

		qualifiers := trustService.GetQualifiers()
		if IsQcForESeal(qualifiers) || IsQcForWSA(qualifiers) {
			return false
		}
	}

	// TODO The organizationIdentifier or the issuerAltName of the sigCert shall match the TSP Name or the TSP trade name

	return true
}

func getCorrespondingASIForCurrentUsageQC(qualifiers []ServiceQualification) AdditionalServiceInformation {
	mapping := map[ServiceQualification]AdditionalServiceInformation{
		ServiceQualificationQCForESig:  ASIForESignatures,
		ServiceQualificationQCForESeal: ASIForESeals,
		ServiceQualificationQCForWSA:   ASIForWebAuthentication,
	}

	for _, qualifier := range qualifiers {
		if slices.Contains(maps.Keys(mapping), qualifier) {
			return mapping[qualifier]
		}
	}

	return ""
}
