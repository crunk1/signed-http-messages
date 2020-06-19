package signedhttpmessages

import (
	"net/http"
	"net/url"
	"testing"
	"time"
)

func TestSigParams_fromHTTPHeaderValue(t *testing.T) {
	cases := []struct {
		headerValue string

		want *SigParams
		wantErr bool
		wantErrCode int
	} {
		{},
	}

	for ci, c := range cases {
		got, err := fromSignatureHeaderValue(c.headerValue)
	}
}

func TestSigParams_toHTTPHeaderValue(t *testing.T) {

}

func TestSigParams_validate(t *testing.T) {
	cases := []struct {
		algo        Algorithm
		wantErr     bool
		wantErrCode int
	}{
		{HS2019, false, 0},
		{"bad", true, errorCodeSigParamInvalidAlgorithm},
	}

	now := time.Now()
	sp := &SigParams{KeyID: "foo", Signature: "bar", Created: &now}
	for ci, c := range cases {
		sp.Algorithm = &c.algo
		err := sp.validate(nil)
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateCoveredContent(t *testing.T) {
	now := time.Now()
	cases := []struct {
		headers     []string
		wantErr     bool
		wantErrCode int
	}{
		{[]string{"(created)", "(expires)", "(request-target)", "foo-header"}, false, 0},
		{[]string{"(created)", "(expires)", "(created)", "(request-target)", "foo-header"}, true, errorCodeSigParamHeadersIdentifiersDupe},
	}

	req, _ := http.NewRequest("GET", "/foo?bar=baz&bar=gaz", nil)
	req.Header.Add("foo-header", "fooHeaderValue")
	sp := &SigParams{Created: &now, Expires: &now}
	for ci, c := range cases {
		sp.Headers = c.headers
		err := sp.validateCoveredContent(req)
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateCoveredContentCreated(t *testing.T) {
	algo := HMACSHA256
	now := time.Now()
	cases := []struct {
		sp          *SigParams
		wantErr     bool
		wantErrCode int
	}{
		{&SigParams{Created: &now}, false, 0},
		{&SigParams{}, true, errorCodeSigParamHeadersIdentifiersCreatedMissing},
		{&SigParams{Algorithm: &algo, Created: &now}, true, errorCodeSigParamHeadersIdentifiersCreatedInvalidAlgorithm},
	}

	for ci, c := range cases {
		err := c.sp.validateCoveredContentCreated()
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateCoveredContentExpires(t *testing.T) {
	algo := HMACSHA256
	now := time.Now()
	cases := []struct {
		sp          *SigParams
		wantErr     bool
		wantErrCode int
	}{
		{&SigParams{Expires: &now}, false, 0},
		{&SigParams{}, true, errorCodeSigParamHeadersIdentifiersExpiresMissing},
		{&SigParams{Algorithm: &algo, Expires: &now}, true, errorCodeSigParamHeadersIdentifiersExpiresInvalidAlgorithm},
	}

	for ci, c := range cases {
		err := c.sp.validateCoveredContentExpires()
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateCoveredContentHeader(t *testing.T) {
	cases := []struct {
		req         *http.Request
		headerKey   string
		wantErr     bool
		wantErrCode int
	}{
		{&http.Request{Header: map[string][]string{"Foo": {"bar"}}}, "foo", false, 0},
		{&http.Request{Header: map[string][]string{"Foo": {"bar"}}}, "baz", true, errorCodeSigParamHeadersIdentifiersHeaderMissing},
		{&http.Request{}, "baz", true, errorCodeSigParamHeadersIdentifiersHeaderMissing},
	}

	sp := &SigParams{}
	for ci, c := range cases {
		err := sp.validateCoveredContentHeader(c.req, c.headerKey)
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateCoveredContentRequestTarget(t *testing.T) {
	u, _ := url.Parse("/foo?bar=baz&bar=gaz")
	cases := []struct {
		req         *http.Request
		wantErr     bool
		wantErrCode int
	}{
		{&http.Request{Method: "GET", URL: u}, false, 0},
		{&http.Request{Method: "bad", URL: u}, true, errorCodeInvalidRequestTargetMethod},
		{&http.Request{Method: "GET"}, true, errorCodeInvalidRequestTargetURI},
	}

	sp := &SigParams{}
	for ci, c := range cases {
		err := sp.validateCoveredContentRequestTarget(c.req)
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}

func TestSigParams_validateRequiredParams(t *testing.T) {
	now := time.Now()
	cases := []struct {
		sp          *SigParams
		wantErr     bool
		wantErrCode int
	}{
		{&SigParams{KeyID: "foo", Signature: "bar", Created: &now}, false, 0},
		{&SigParams{KeyID: "foo", Created: &now}, true, errorCodeSigParamRequiredSignature},
		{&SigParams{Signature: "bar", Created: &now}, true, errorCodeSigParamRequiredKeyID},
	}

	for ci, c := range cases {
		err := c.sp.validateRequiredParams()
		if err != nil {
			if c.wantErr && c.wantErrCode == err.Code {
				continue // expected error
			}
			t.Errorf("case %d - unexpected error: %+v", ci, err)
		} else if c.wantErr {
			t.Errorf("case %d - should have erred but didn't", ci)
		}
	}
}
