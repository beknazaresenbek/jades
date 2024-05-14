package certificate

import "golang.org/x/exp/slices"

func IsForESignatures(additionalServiceInfos []AdditionalServiceInformation) bool {
	return slices.Contains(additionalServiceInfos, ASIForESignatures)
}

func IsForESeals(additionalServiceInfos []AdditionalServiceInformation) bool {
	return slices.Contains(additionalServiceInfos, ASIForESeals)
}

func IsForWebAuth(additionalServiceInfos []AdditionalServiceInformation) bool {
	return slices.Contains(additionalServiceInfos, ASIForWebAuthentication)
}

func IsForeSealsOnly(additionalServiceInfos []AdditionalServiceInformation) bool {
	return len(additionalServiceInfos) == 1 && IsForESeals(additionalServiceInfos)
}

func IsForWebAuthOnly(additionalServiceInfos []AdditionalServiceInformation) bool {
	return len(additionalServiceInfos) == 1 && IsForWebAuth(additionalServiceInfos)
}
