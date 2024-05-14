package certificate

type CertificateChainItem struct {
	cert *CertificateWrapper
}

func (ci *CertificateChainItem) SetCertificate(cert *CertificateWrapper) {
	ci.cert = cert
}
