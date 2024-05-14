package signature

//go:generate enumgen

type SigScopeType int32 //enums:enum

const (
	SigScopeTypeFull SigScopeType = iota
	SigScopeTypePartial
)

type SigScope struct {
	scope SigScopeType
}

func (s *SigScope) GetScope() SigScopeType {
	return s.scope
}
