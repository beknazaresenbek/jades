package certificate

import "golang.org/x/exp/slices"

func IsQCPPlus(certificate *CertificateWrapper) bool {
	return hasPolicyIdOID(certificate, &PolicyQcpPublicWithSSCD)
}

func IsQCP(certificate *CertificateWrapper) bool {
	return hasPolicyIdOID(certificate, &PolicyQcpPublic)
}

func hasPolicyIdOID(certificate *CertificateWrapper, policy *Policy) bool {
	return slices.Contains(certificate.GetPolicyIds(), policy.oid)
}
