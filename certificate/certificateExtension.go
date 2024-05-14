package certificate

type CertificateExtensionEnum struct {
	oid         string
	description string
}

func (enum *CertificateExtensionEnum) GetOid() string {
	return enum.oid
}

var (
	CertificateExtensionNameConstraints = CertificateExtensionEnum{"2.5.29.30", "nameConstraints"}
)

type CertificateExtension struct {
	oid         string
	description string
	critical    bool
}

func (ce *CertificateExtension) SetOID(value string) {
	ce.oid = value
}
