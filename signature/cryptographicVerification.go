package signature

type CryptographicVerification struct {
}

func (cv *CryptographicVerification) Execute() *CVConstraintsConclusion {
	return &CVConstraintsConclusion{}
}
