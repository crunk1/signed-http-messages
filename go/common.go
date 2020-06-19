package signedhttpmessages

import (
	"net/http"
	"strings"
)

var enumLoweredHTTPMethods = [...]string{
	strings.ToLower(http.MethodGet),
	strings.ToLower(http.MethodHead),
	strings.ToLower(http.MethodPost),
	strings.ToLower(http.MethodPut),
	strings.ToLower(http.MethodPatch),
	strings.ToLower(http.MethodDelete),
	strings.ToLower(http.MethodConnect),
	strings.ToLower(http.MethodOptions),
	strings.ToLower(http.MethodTrace),
}

func strIn(s string, ss ...string) bool {
	for _, elem := range ss {
		if s == elem {
			return true
		}
	}
	return false
}

func strOr(s string, ss ...string) string {
	if s != "" {
		return s
	}
	for _, s := range ss {
		if s != "" {
			return s
		}
	}
	return ""
}
