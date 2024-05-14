package certificate

type DistinguishedName struct {
	value  string
	format string
}

func (dn *DistinguishedName) SetFormat(format string) {
	dn.format = format
}

func (dn *DistinguishedName) SetValue(value string) {
	dn.value = value
}
