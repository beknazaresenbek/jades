package certificate

type NameConstraints struct {
	*CertificateExtension
	permittedSubtrees []GeneralSubtree
	excludedSubtrees  []GeneralSubtree
}

func (cn *NameConstraints) AddPermittedSubtree(subtree GeneralSubtree) {
	cn.permittedSubtrees = append(cn.permittedSubtrees, subtree)
}
