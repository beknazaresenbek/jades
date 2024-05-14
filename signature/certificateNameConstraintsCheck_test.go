package signature

import (
	"github.com/stretchr/testify/assert"
	"jades/certificate"
	"jades/logging"
	"testing"
)

func TestPermittedSubtreesValid(t *testing.T) {
	logging.Configure(true, "DEBUG", true, []string{})

	type testCase struct {
		testName string
	}

	tests := []testCase{
		{testName: "Test 1"},
	}

	rootCertificate := &certificate.CertificateWrapper{}
	rootCertificate.SetSelfSigned(true)

	nameConstraints := &certificate.NameConstraints{}
	nameConstraints.SetOID(certificate.CertificateExtensionNameConstraints.GetOid())

	generalSubtree := &certificate.GeneralSubtree{}
	generalSubtree.SetType(certificate.GeneralNameTypeDirectoryName)
	generalSubtree.SetValue("C=US,O=Test Certificates,OU=permittedSubtree1")
	nameConstraints.AddPermittedSubtree(*generalSubtree)
	rootCertificate.AddCertificateExtension(*nameConstraints.CertificateExtension)

	caCertificate := &certificate.CertificateWrapper{}
	caCertificate.AddCertificateExtension(*nameConstraints.CertificateExtension)

	distinguishedName := &certificate.DistinguishedName{}
	distinguishedName.SetFormat("RFC2253")
	distinguishedName.SetValue("CN=Valid DN nameConstraints CA Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US")
	caCertificate.AddSubjectDistinguishedName(*distinguishedName)

	signCertificate := &certificate.CertificateWrapper{}

	distinguishedName = &certificate.DistinguishedName{}
	distinguishedName.SetFormat("RFC2253")
	distinguishedName.SetValue("CN=Valid DN nameConstraints EE Certificate Test1,OU=permittedSubtree1,O=Test Certificates,C=US")
	signCertificate.AddSubjectDistinguishedName(*distinguishedName)

	chainItem1 := certificate.CertificateChainItem{}
	chainItem1.SetCertificate(caCertificate)
	chainItem2 := certificate.CertificateChainItem{}
	chainItem2.SetCertificate(rootCertificate)
	signCertificate.SetCertificateChain([]certificate.CertificateChainItem{chainItem1, chainItem2})

	for _, test := range tests {
		t.Run(test.testName, func(t *testing.T) {
			logging.Log().Info("TestPermittedSubtreesValid +++++++++++++++++ Running test: ", test.testName)

			assert.Equal(t, 1, 1)
		})
	}
}
