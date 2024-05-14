package certificate

import "time"

func IsPostEIDAS(date time.Time) bool {
	return date.Equal(EidasDate) || date.After(EidasDate)
}
