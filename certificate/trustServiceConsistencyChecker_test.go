package certificate

import (
	"github.com/stretchr/testify/assert"
	"jades/logging"
	"testing"
)

func TestTrustServiceConsistencyChecker_IsConsistent(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName     string
		qualifiers   []ServiceQualification
		isConsistent bool
	}

	consistencyChecker := new(TrustServiceConsistencyChecker)
	trustService := TrustService{}

	tests := []test{
		{"TS is not consistent with qcStatements QcForLegalPerson and QcForeSig",
			[]ServiceQualification{ServiceQualificationQcForLegalPerson, ServiceQualificationQCForESig}, false},
		{"TS is not consistent with qcStatements QcStatement and NotQualified",
			[]ServiceQualification{ServiceQualificationQCStatement, ServiceQualificationNotQualified}, false},
		{"TS is not consistent with multiple usage qcStatements - ESig, WSA",
			[]ServiceQualification{ServiceQualificationQCForESig, ServiceQualificationQCForWSA}, false},
		{"TS is not consistent with multiple usage qcStatements - ESig, ESeal, WSA",
			[]ServiceQualification{ServiceQualificationQCForESig, ServiceQualificationQCForESeal, ServiceQualificationQCForWSA}, false},
		{"TS is consistent with one of usage qcStatements - ESig",
			[]ServiceQualification{ServiceQualificationQCForESig}, true},
		{"TS is consistent with one of usage qcStatements - ESeal",
			[]ServiceQualification{ServiceQualificationQCForESeal}, true},
		{"TS is not consistent with qcStatements QcNoQSCD and QcWithQSCD",
			[]ServiceQualification{ServiceQualificationQcNoQSCD, ServiceQualificationQcWithQSCD}, false},
		{"TS is not consistent with qcStatements QcQSCDStatusAsInCert and QcWithQSCD",
			[]ServiceQualification{ServiceQualificationQcQSCDStatusAsInCert, ServiceQualificationQcWithQSCD}, false},
	}

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			logging.Log().Info("TestTrustServiceConsistencyChecker_IsConsistent +++++++++++++++++ Running test: ", test.testName)

			trustService.qualifiers = test.qualifiers
			assert.Equal(t, test.isConsistent, consistencyChecker.IsConsistent(&trustService))
		})
	}
}

type Ai interface {
	Meth1()
}

type A1 struct {
	Ai
	str string
}

func (a *A1) Exec() {
	print("A1 Exec")
	a.Meth1()
}

func (a *A1) Meth1() {
	print("A1 Meth1")
}

type A2 struct {
	A1
}

func (a *A2) Meth1() {
	print("A2 meth1")
}

func TestTmp(t *testing.T) {
	a2 := new(A2)
	a2.Exec()
}
