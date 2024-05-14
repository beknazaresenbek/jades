package signature

import "golang.org/x/exp/slices"

//go:generate enumgen

type Level int32 //enums:enum

const (
	LevelFail Level = iota
	LevelWarn
	LevelInform
	LevelIgnore
)

type LevelConstraint interface {
	GetLevel() *Level
}

type BaseConstraint struct {
	level Level
}

func (l *BaseConstraint) GetLevel() *Level {
	return &l.level
}

type MultiValuesConstraint struct {
	id []string
	*BaseConstraint
}

func (m *MultiValuesConstraint) GetId() []string {
	return m.id
}

type TimeConstraint struct {
	*BaseConstraint
	unit  string
	value string
}

func (t *TimeConstraint) GetUnit() string {
	return t.unit
}

func (t *TimeConstraint) GetValue() string {
	return t.value
}

type CryptographicConstraint struct {
	*BaseConstraint
}

type BasicSignatureConstraints struct {
	signatureDuplicated *BaseConstraint
}

type SignatureConstraints struct {
	acceptableFormats *MultiValuesConstraint
}

type CertificateConstraints struct {
	recognition *BaseConstraint
}

type MultiValuesConstraintChecker struct {
}

func (m *MultiValuesConstraintChecker) check(values []string, value string) bool {
	return slices.Contains(values, "*") || slices.Contains(values, value)
}
