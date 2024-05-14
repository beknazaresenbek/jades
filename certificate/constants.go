package certificate

import (
	"golang.org/x/crypto/cryptobyte"
	"time"
)

type ServiceQualification string

const (
	ServiceQualificationQCStatement           ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCStatement"
	ServiceQualificationNotQualified          ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/NotQualified"
	ServiceQualificationQCForESig             ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESig"
	ServiceQualificationQCForESeal            ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForESeal"
	ServiceQualificationQCForWSA              ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForWSA"
	ServiceQualificationQcWithQSCD            ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithQSCD"
	ServiceQualificationQcQSCDManagedOnBehalf ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDManagedOnBehalf"
	ServiceQualificationQcQSCDStatusAsInCert  ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCQSCDStatusAsInCert"
	ServiceQualificationQcNoQSCD              ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoQSCD"
	ServiceQualificationQcWithSSCD            ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCWithSSCD"
	ServiceQualificationQcSSCDManagedOnBehalf ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDManagedOnBehalf"
	ServiceQualificationQcSSCDStatusAsInCert  ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCSSCDStatusAsInCert"
	ServiceQualificationQcNoSSCD              ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCNoSSCD"
	ServiceQualificationQcForLegalPerson      ServiceQualification = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/QCForLegalPerson"
)

type Policy struct {
	description string
	oid         string
}

var (
	PolicyQcpPublic         = Policy{"qcp-public", "0.4.0.1456.1.2"}
	PolicyQcpPublicWithSSCD = Policy{"qcp-public-with-sscd", "0.4.0.1456.1.1"}
)

type QualifiedStatus string

const (
	QualifiedStatusQC    QualifiedStatus = "Qualified"
	QualifiedStatusNotQC QualifiedStatus = "Not qualified"
)

type CertType string

const (
	CertTypeESign   CertType = "eSig"
	CertTypeESeal   CertType = "eSeal"
	CertTypeWSA     CertType = "WSA"
	CertTypeUnknown CertType = "unknown"
)

type QSCDStatus string

const (
	QSCDStatusQSCD    QSCDStatus = "QSCD"
	QSCDStatusNotQSCD QSCDStatus = "NOT_QSCD"
)

type Qualification struct {
	readable        string
	label           string
	qualifiedStatus QualifiedStatus
	certType        CertType
	qscdStatus      QSCDStatus
}

func (q *Qualification) IsQC() bool {
	return q.qualifiedStatus == QualifiedStatusQC
}

func (q *Qualification) GetCertType() CertType {
	return q.certType
}

func (q *Qualification) IsQSCD() bool {
	return q.qscdStatus == QSCDStatusQSCD
}

var (
	QualificationNA = Qualification{"N/A", "Not applicable", QualifiedStatusNotQC, CertTypeUnknown, QSCDStatusNotQSCD}
)

type AdditionalServiceInformation string

const (
	ASIForESignatures       AdditionalServiceInformation = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSignatures"
	ASIForESeals            AdditionalServiceInformation = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForeSeals"
	ASIForWebAuthentication AdditionalServiceInformation = "http://uri.etsi.org/TrstSvc/TrustedList/SvcInfoExt/ForWebSiteAuthentication"
)

type ExtensionEnum struct {
	description string
	oid         string
}

var (
	ExtensionQCStatements = ExtensionEnum{"QcStatements", "1.3.6.1.5.5.7.1.3"}
)

var EidasDate, _ = time.Parse(time.RFC3339, "2016-06-30T22:00:00.000Z")

type QcStatementValue struct {
	description string
	oid         string
}

var (
	QcStatementQcCompliance = QcStatementValue{"qc-compliance", "0.4.0.1862.1.1"} // id-etsi-qcs-QcCompliance
	QcStatementQcSSCD       = QcStatementValue{"qc-sscd", "0.4.0.1862.1.4"}       // id-etsi-qcs-QcSSCD
	QcStatementQcType       = QcStatementValue{"qc-type", "0.4.0.1862.1.6"}       // id-etsi-qcs-QcType
)

type QcStatements struct {
	Raw          cryptobyte.String
	QcCompliance bool
	QcSSCD       bool
	QcTypes      []string
}

type ValidationTime string

const (
	VTCertificateIssuanceTime ValidationTime = "CertificateIssueTime"
	VTValidationTime          ValidationTime = "ValidationTime"
)

type TrustServiceStatus struct {
	shortName string
	uri       string
	postEidas bool
	valid     bool
}

var (
	TSSAccredited             = TrustServiceStatus{"accredited", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/accredited", false, true}
	TSSUnderSupervision       = TrustServiceStatus{"under supervision", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/undersupervision", false, true}
	TSSSupervisionInCessation = TrustServiceStatus{"supervision in cessation", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/supervisionincessation", false, true}
	TSSGranted                = TrustServiceStatus{"granted", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/granted", true, true}
	TSSWithdrawn              = TrustServiceStatus{"withdrawn", "http://uri.etsi.org/TrstSvc/TrustedList/Svcstatus/withdrawn", true, false}
)

var TSSValues = []TrustServiceStatus{
	TSSAccredited,
	TSSUnderSupervision,
	TSSSupervisionInCessation,
	TSSGranted,
	TSSWithdrawn,
}

type QcType struct {
	description string
	oid         string
}

var (
	QcTypeESign = QcType{"qc-type-esign", "0.4.0.1862.1.6.1"} // id-etsi-qct-esign
	QcTypeESeal = QcType{"qc-type-eseal", "0.4.0.1862.1.6.2"} // id-etsi-qct-eseal
	QcTypeWeb   = QcType{"qc-type-web", "0.4.0.1862.1.6.3"}   // id-etsi-qct-web
)
