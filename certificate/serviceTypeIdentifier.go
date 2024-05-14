package certificate

type ServiceTypeIdentifier struct {
	shortName string
	uri       string
	qualified bool
}

var (
	CAQC = ServiceTypeIdentifier{"CA/QC", "http://uri.etsi.org/TrstSvc/Svctype/CA/QC", true}
)

func isCaQc(serviceTypeIdentifier string) bool {
	return serviceTypeIdentifier == CAQC.uri
}
