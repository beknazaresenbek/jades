package signature

import "time"

type RevocationType int

const (
	RevocationTypeCRL RevocationType = iota
	RevocationTypeOCSP
)

type RevocationWrapper struct {
}

func (rw *RevocationWrapper) GetRevocationType() RevocationType {
	return RevocationTypeCRL
}

func (rw *RevocationWrapper) GetNextUpdate() *time.Time {
	now := time.Now()
	return &now
}

func (rw *RevocationWrapper) GetThisUpdate() *time.Time {
	now := time.Now()
	return &now
}
