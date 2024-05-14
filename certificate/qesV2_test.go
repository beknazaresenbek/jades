package certificate

import (
	"github.com/stretchr/testify/assert"
	"jades/logging"
	"testing"
)

//func TestCertIsQCForESigESealAtIssuance(t *testing.T) {
//	logging.Configure(true, "DEBUG", true, []string{})
//
//	type test struct {
//		testName    string
//		certWrapper *CertificateWrapper
//	}
//
//	tests := []test{
//		{"MyTest1", &CertificateWrapper{qcStatements: &QcStatements{}}},
//	}
//
//	for _, test := range tests {
//		t.Run(test.testName, func(t *testing.T) {
//			logging.Log().Info("TestCertIsQCForESigESealAtIssuance +++++++++++++++++ Running test: ", test.testName)
//
//		})
//	}
//}

func TestFindCatchingTLs(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName       string
		cert           *CertificateWrapper
		trustedList    []TrustService
		catchingTLs    []TrustService
		validationTime ValidationTime
	}

	tests := []test{
		{"If trusted list is empty, there will not be a catching service", &CertificateWrapper{},
			make([]TrustService, 0), make([]TrustService, 0), VTCertificateIssuanceTime},
		{"Sie:aSI:ForeSignatures catches cert with QcType eSeal if Sie:Q:QcForeSig catches cert",
			&CertificateWrapper{
				qcStatements: &QcStatements{
					QcTypes: []string{QcTypeESeal.oid},
				},
			},
			[]TrustService{
				{
					qualifiers:             []ServiceQualification{ServiceQualificationQCForESig},
					additionalServiceInfos: []AdditionalServiceInformation{ASIForESignatures},
				},
			},
			[]TrustService{
				{
					qualifiers:             []ServiceQualification{ServiceQualificationQCForESig},
					additionalServiceInfos: []AdditionalServiceInformation{ASIForESignatures},
				},
			},
			VTCertificateIssuanceTime,
		},
	}

	trustServiceFinder := TrustServiceFinderImpl{}
	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			logging.Log().Info("TestFindCatchingTLs +++++++++++++++++ Running test: ", test.testName)

			assert.Equal(t, test.catchingTLs, trustServiceFinder.FindCatching(test.cert, test.validationTime))
		})
	}
}
