package signature

//go:generate enumgen

type SigForm int32 //enums:enum

const (
	SigFormPAdES SigForm = iota
	SigFormJAdES
	SigFormUnknown
)

type SigLevel string

const (
	SigLevelJAdESBaselineB   SigLevel = "JAdES-BASELINE-B"
	SigLevelJAdESBaselineT   SigLevel = "JAdES-BASELINE-T"
	SigLevelJAdESBaselineLT  SigLevel = "JAdES-BASELINE-LT"
	SigLevelJAdESBaselineLTA SigLevel = "JAdES-BASELINE-LTA"
)

func (s SigLevel) GetSigForm() SigForm {
	switch s {
	case SigLevelJAdESBaselineB:
	case SigLevelJAdESBaselineT:
	case SigLevelJAdESBaselineLT:
	case SigLevelJAdESBaselineLTA:
		return SigFormJAdES
	}
	return SigFormUnknown
}
