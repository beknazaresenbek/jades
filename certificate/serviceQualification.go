package certificate

import "slices"

func IsQcForESig(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQCForESig)
}

func IsQcForESeal(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQCForESeal)
}

func IsQcForWSA(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQCForWSA)
}

func IsQcForLegalPerson(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcForLegalPerson)
}

func IsNotQualified(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationNotQualified)
}

func IsQCStatement(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQCStatement)
}

func IsQcWithQSCD(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcWithQSCD)
}

func IsQcQSCDManagedOnBehalf(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcQSCDManagedOnBehalf)
}

func IsQcQSCDStatusAsInCert(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcQSCDStatusAsInCert)
}

func IsQcNoQSCD(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcNoQSCD)
}

func IsQcWithSSCD(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcWithSSCD)
}

func IsQcSSCDManagedOnBehalf(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcSSCDManagedOnBehalf)
}

func IsQcSSCDStatusAsInCert(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcSSCDStatusAsInCert)
}

func IsQcNoSSCD(qualifiers []ServiceQualification) bool {
	return slices.Contains(qualifiers, ServiceQualificationQcNoSSCD)
}

func FilterUsageQualifiers(qualifiers []ServiceQualification) []ServiceQualification {
	usageQualifiers := []ServiceQualification{ServiceQualificationQCForESig, ServiceQualificationQCForESeal,
		ServiceQualificationQCForWSA}
	result := make([]ServiceQualification, 0)
	for _, qualifier := range qualifiers {
		if slices.Contains(usageQualifiers, qualifier) {
			result = append(result, qualifier)
		}
	}
	return result
}
