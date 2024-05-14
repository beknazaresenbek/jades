package signature

import (
	"github.com/stretchr/testify/assert"
	"jades/logging"
	"testing"
)

type ValidationPolicyMock struct {
	sigFormat *MultiValuesConstraint
}

func (vp *ValidationPolicyMock) GetSigningCertificateRecognitionConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignatureFormatConstraint() *MultiValuesConstraint {
	return vp.sigFormat
}

func (vp *ValidationPolicyMock) GetSignatureDuplicatedConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSigningCertificateDigestValuePresentConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignaturePolicyConstraint() *MultiValuesConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignaturePolicyIdentifiedConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignaturePolicyStorePresentConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignaturePolicyPolicyHashValid() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetProspectiveCertificateChainConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetFullScopeConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetEllipticCurveKeySizeConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSigningCertificateDigestValueMatchConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSigningCertificateIssuerSerialMatchConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetRevocationFreshnessConstraint() *TimeConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetCRLNextUpdatePresentConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetOCSPNextUpdatePresentConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetRevocationFreshnessNextUpdateConstraint() *BaseConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetSignatureCryptographicConstraint() *CryptographicConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetTrustServiceTypeIdentifierConstraint() *MultiValuesConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetTrustServiceStatusConstraint() *MultiValuesConstraint {
	return nil
}

func (vp *ValidationPolicyMock) GetValidationModel() ValidationModel {
	return ValidationModelChain
}

func TestBasicBuildingBlocks_FormatChecking(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	type test struct {
		testName           string
		signature          *SignatureWrapper
		validationPolicy   ValidationPolicy
		expectedConclusion *Conclusion
	}

	testCases := []test{
		{
			testName:           "Basic signature format checking",
			signature:          &SignatureWrapper{},
			validationPolicy:   &ValidationPolicyMock{sigFormat: &MultiValuesConstraint{[]string{"*"}, &BaseConstraint{level: LevelFail}}},
			expectedConclusion: &Conclusion{indication: &IndicationPassed},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.testName, func(t *testing.T) {
			logging.Log().Info("TestBasicBuildingBlocks_FormatChecking +++++++++++++++++ Running test: ", tc.testName)

			bbb := BasicBuildingBlocks{}
			bbb.executeFormatChecking()
			assert.Equal(t, tc.expectedConclusion, bbb.GetBBBConclusion().GetConclusion())
		})
	}
}
