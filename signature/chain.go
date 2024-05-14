package signature

import "github.com/sirupsen/logrus"

type AbstractChainItem interface {
	process() bool
	getFailedIndicationForConclusion() *Indication
	getFailedSubIndicationForConclusion() *SubIndication
}

type ChainItem struct {
	constraint LevelConstraint
	nextItem   *ChainItem
	current    AbstractChainItem
	result     ConstraintsConclusion
	bbbId      string
	log        *logrus.Logger
}

func (ci *ChainItem) SetNextItem(nextItem *ChainItem) *ChainItem {
	ci.nextItem = nextItem
	return nextItem
}

func (ci *ChainItem) GetLevel() *Level {
	if ci.constraint != nil {
		return ci.constraint.GetLevel()
	} else {
		return nil
	}
}

func (ci *ChainItem) Execute() {
	level := ci.GetLevel()
	if level == nil {
		ci.log.Trace("Check skipped : constraint not defined")
		ci.callNext()
	} else {
		switch *level {
		case LevelIgnore:
			ci.ignore()
			break
		case LevelFail:
			ci.fail()
			break
		case LevelInform:
		case LevelWarn:
			ci.informOrWarn(level)
			break
		default:
			ci.log.Warnf("Unknown level : %s", level)
		}
	}
}

func (ci *ChainItem) callNext() {
	if ci.nextItem != nil {
		ci.nextItem.Execute()
	}
}

func (ci *ChainItem) ignore() {
	ci.recordIgnore()
	ci.callNext()
}

func (ci *ChainItem) recordIgnore() {}

func (ci *ChainItem) recordValid() {}

func (ci *ChainItem) recordInvalid() {}

func (ci *ChainItem) recordConclusion() {
	conclusion := &Conclusion{}
	conclusion.SetIndication(ci.current.getFailedIndicationForConclusion())
	conclusion.SetSubIndication(ci.current.getFailedSubIndicationForConclusion())
	ci.result.SetConclusion(conclusion)
}

func (ci *ChainItem) getSuccessIndication() *Indication {
	return nil
}

func (ci *ChainItem) isCustomSuccessConclusion() bool {
	return ci.getSuccessIndication() != nil
}

func (ci *ChainItem) recordCustomSuccessConclusion() {}

func (ci *ChainItem) fail() {
	valid := ci.current.process()
	if valid {
		ci.recordValid()
		if !ci.isCustomSuccessConclusion() {
			ci.callNext()
		} else {
			ci.recordCustomSuccessConclusion()
		}
	} else {
		ci.recordValid()
		ci.recordConclusion()
	}
}

func (ci *ChainItem) informOrWarn(level *Level) {
	valid := ci.current.process()
	if valid {
		ci.recordValid()
	} else {
		ci.recordInfosOrWarns(level)
	}
	ci.callNext()
}

func (ci *ChainItem) recordInfosOrWarns(level *Level) {}

func (ci *ChainItem) addConstraint(constraint *Constraint) {
	ci.result.constraint = append(ci.result.constraint, *constraint)
}

type Chain struct {
	result    ConstraintsConclusion
	firstItem *ChainItem
}
