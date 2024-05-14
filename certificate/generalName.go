package certificate

type GeneralNameType struct {
	index int
	label string
}

var (
	GeneralNameTypeDirectoryName = GeneralNameType{4, "directoryName"}
)

type GeneralName struct {
	value           string
	generalNameType *GeneralNameType
}

func (cn *GeneralName) SetType(generalNameType GeneralNameType) {
	cn.generalNameType = &generalNameType
}

func (cn *GeneralName) SetValue(value string) {
	cn.value = value
}

type GeneralSubtree struct {
	*GeneralName
	minimum int64
	maximum int64
}
