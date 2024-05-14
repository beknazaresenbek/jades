package signature

type EncryptionAlgorithm struct {
}

type DigestAlgorithm struct {
	name string
}

var (
	DigestAlgorithmSHA256 = DigestAlgorithm{"SHA256"}
	DigestAlgorithmSHA384 = DigestAlgorithm{"SHA384"}
	DigestAlgorithmSHA512 = DigestAlgorithm{"SHA512"}
)

func (alg *DigestAlgorithm) GetName() string {
	return alg.name
}

func (alg *EncryptionAlgorithm) IsEquivalent(encryptionAlgorithm EncryptionAlgorithm) bool {
	return true
}

var (
	EncryptionAlgorithmECDSA = EncryptionAlgorithm{}
)
