package certificate

func isAcceptableStatusBeforeEIDAS(uri string) bool {
	tss := findTSS(uri)
	return tss != nil && !tss.postEidas && tss.valid
}

func isAcceptableStatusAfterEIDAS(uri string) bool {
	tss := findTSS(uri)
	return tss != nil && tss.postEidas && tss.valid
}

func findTSS(uri string) *TrustServiceStatus {
	for _, tssValue := range TSSValues {
		if uri == tssValue.uri {
			return &tssValue
		}
	}
	return nil
}
