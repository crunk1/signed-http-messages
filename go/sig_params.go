package signedhttpmessages

import (
	"bytes"
	"fmt"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	sigParamsDefaultAlgorithm = HS2019
	sigParamsDefaultHeaders   = []string{"(created)"}

	sigHeaderRgxAlgorithm = regexp.MustCompile(fmt.Sprintf(`^algorithm="(?P<algorithm>%s)"$`, strings.Join(allAlgorithmStrs, "|")))
	sigHeaderRgxKeyID     = regexp.MustCompile(`^keyId="([\x20-\x7F]*)"$`) // Only allow printable ASCII.
	sigHeaderRgxCreated   = regexp.MustCompile(`^created=(\d*)$`)
	sigHeaderRgxExpires   = regexp.MustCompile(`^expires=(\d*)$`)
	sigHeaderRgxHeaders   = regexp.MustCompile(`^headers="(|([\x21-\x39\x3B-\x40\x5B-\x7E]+)( [\x21-\x39\x3B-\x40\x5B-\x7E]+)*)"$`) // Valid identifier characters (lowercase printable ASCII, except colon/space/del): [\x21-\x39\x3B-\x40\x5B-\x7E]
	sigHeaderRgxSig       = regexp.MustCompile(`^signature="(([A-Za-z0-9+/]{4})+([A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?)"$`)        // Valid base64 string.
)

// SigParams are the signature parameters.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-4.1
type SigParams struct {
	// REQUIRED params.
	// KeyID: US-ASCII identifier for the key to use to sign/verify this signature.
	KeyID string
	// Signature: signature value in Base64.
	// This param is automatically generated and user input to Sign will be ignored.
	Signature string

	// OPTIONAL params.
	// Algorithm: signature/HMAC algorithm to use to sign/verify this signature. Defaults to "hs2019"
	Algorithm *Algorithm
	// Created: RECOMMENDED creation time of the signature.
	Created *time.Time
	// Expires: expiration time of the signature. If nil, no expiration will be set.
	Expires *time.Time
	// Headers: list of headers to be included into the signature input. If nil, defaults to []string{"(created)"}.
	// Headers may also contain identifiers to signature parameters via their identifiers.
	Headers []string
}

func fromSignatureHeaderValue(hv string, req *http.Request) (*SigParams, *codedError) {
	sp := &SigParams{}
	params := strings.Split(hv, ", ")
	for _, param := range params {
		if m := sigHeaderRgxAlgorithm.FindStringSubmatch(param); m != nil {
			if sp.Algorithm != nil {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamAlgorithm, `duplicate signature header "algorithm" parameter`)
			}
			algorithm := Algorithm(m[1])
			sp.Algorithm = &algorithm
		} else if m := sigHeaderRgxKeyID.FindStringSubmatch(param); m != nil {
			if sp.KeyID != "" {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamKeyID, `duplicate signature header "keyId" parameter`)
			}
			sp.KeyID = m[1]
		} else if m := sigHeaderRgxCreated.FindStringSubmatch(param); m != nil {
			if sp.Created != nil {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamCreated, `duplicate signature header "created" parameter`)
			}
			epoch, _ := strconv.ParseInt(m[1], 10, 64)
			t := time.Unix(epoch, 0).UTC()
			sp.Created = &t
		} else if m := sigHeaderRgxExpires.FindStringSubmatch(param); m != nil {
			if sp.Expires != nil {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamExpires, `duplicate signature header "expires" parameter`)
			}
			epoch, _ := strconv.ParseInt(m[1], 10, 64)
			t := time.Unix(epoch, 0).UTC()
			sp.Expires = &t
		} else if m := sigHeaderRgxHeaders.FindStringSubmatch(param); m != nil {
			if sp.Headers != nil {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamHeaders, `duplicate signature header "headers" parameter`)
			}
			sp.Headers = strings.Split(m[1], " ")

		} else if m := sigHeaderRgxSig.FindStringSubmatch(param); m != nil {
			if sp.Signature != "" {
				return nil, newCodedError(errorCodeSigHeaderParseDupeParamSignature, `duplicate signature header "signature" parameter`)
			}
			sp.Signature = m[1]
		} else {
			return nil, codedErrorf(errorCodeSigHeaderParseInvalidParam, "invalid/malformed signature header parameter: %q", param)
		}
	}

	return sp, sp.validate(req)
}

func (sp *SigParams) algorithmOrDefault() *Algorithm {
	if sp.Algorithm != nil {
		return sp.Algorithm
	}
	return &sigParamsDefaultAlgorithm
}

// generateSigInput creates and formats the input to be passed to the signing method.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
func (sp *SigParams) generateSigInput(req *http.Request) ([]byte, *codedError) {
	bb := bytes.NewBuffer(nil)
	for _, h := range sp.Headers {
		var v string

		switch h {
		case "(request-target)":
			// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-2.4
			v = strings.ToLower(req.Method) + " " + req.URL.RequestURI()
		case "(created)":
			v = strconv.FormatInt(sp.Created.Unix(), 10)
		case "(expires)":
			v = strconv.FormatInt(sp.Expires.Unix(), 10)
		default:
			// A canonicalized HTTP header.
			var vals []string
			for _, val := range req.Header[h] {
				vals = append(vals, strings.TrimSpace(val))
			}
			v = strings.Join(vals, ", ")
		}
		_, err := bb.WriteString(h + ": " + v + "\n")
		if err != nil {
			return nil, newCodedError(errorCodeZero, err.Error())
		}
	}
	return bb.Bytes(), nil
}

func (sp *SigParams) headersOrDefault() []string {
	if len(sp.Headers) != 0 {
		return sp.Headers
	}
	return sigParamsDefaultHeaders
}

func (sp *SigParams) toSignatureHeaderValue() string {
	var parts []string
	if sp.Algorithm != nil {
		parts = append(parts, fmt.Sprintf("algorithm=%q", *sp.Algorithm))
	}
	return strings.Join(parts, " ")
}

func (sp *SigParams) validate(req *http.Request) *codedError {
	if algo := sp.algorithmOrDefault(); !algo.isValid() {
		return codedErrorf(errorCodeSigParamInvalidAlgorithm, "invalid algorithm: %q", *algo)
	}

	if err := sp.validateRequiredParams(); err != nil {
		return err
	}

	if err := sp.validateCoveredContent(req); err != nil {
		return err
	}
	return nil
}

func (sp *SigParams) validateCoveredContent(req *http.Request) *codedError {
	// Check headers identifiers for: dupes, missing header, missing created/expires, created/expires used with rsa/hmac/ecdsa algorithms
	// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
	foundIdentifiersSet := map[string]bool{}
	dupeIdentifiersSet := map[string]bool{}
	var dupeIdentifiers []string
	for _, h := range sp.headersOrDefault() {
		if foundIdentifiersSet[h] {
			if !dupeIdentifiersSet[h] {
				dupeIdentifiers = append(dupeIdentifiers, h)
				dupeIdentifiersSet[h] = true
			}
			continue
		}
		foundIdentifiersSet[h] = true
		switch h {
		case "(created)":
			if err := sp.validateCoveredContentCreated(); err != nil {
				return err
			}
		case "(expires)":
			if err := sp.validateCoveredContentExpires(); err != nil {
				return err
			}
		case "(request-target)":
			if err := sp.validateCoveredContentRequestTarget(req); err != nil {
				return err
			}
		default:
			if err := sp.validateCoveredContentHeader(req, h); err != nil {
				return err
			}
		}
	}
	if dupeIdentifiers != nil {
		return codedErrorf(errorCodeSigParamHeadersIdentifiersDupe, `duplicate identifiers in signature "headers" parameter: %v`, dupeIdentifiers)
	}
	return nil
}

// validateCoveredContentCreated checks that (created) -> created is set AND algorithm in hs2019.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
func (sp *SigParams) validateCoveredContentCreated() *codedError {
	if sp.Created == nil {
		return newCodedError(errorCodeSigParamHeadersIdentifiersCreatedMissing, `"(created)" in signature headers param, but created is not set`)
	}
	if algo := sp.algorithmOrDefault(); *algo != HS2019 {
		return codedErrorf(errorCodeSigParamHeadersIdentifiersCreatedInvalidAlgorithm, `"(created)" in signature headers param, algorithm not allowed: %q`, *algo)
	}
	return nil
}

// validateCoveredContentExpires checks that (expires) -> expires is set AND algorithm in hs2019.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
func (sp *SigParams) validateCoveredContentExpires() *codedError {
	if sp.Expires == nil {
		return newCodedError(errorCodeSigParamHeadersIdentifiersExpiresMissing, `"(expires)" in signature headers param, but expires is not set`)
	}
	if algo := sp.algorithmOrDefault(); *algo != HS2019 {
		return codedErrorf(errorCodeSigParamHeadersIdentifiersExpiresInvalidAlgorithm, `"(expires)" in signature headers param, algorithm not allowed: %q`, *algo)
	}
	return nil
}

// validateCoveredContentHeader checks that a header exists in the HTTP request.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
func (sp *SigParams) validateCoveredContentHeader(req *http.Request, headerKey string) *codedError {
	if vals := req.Header.Values(headerKey); vals == nil {
		return codedErrorf(errorCodeSigParamHeadersIdentifiersHeaderMissing, `header %q in signature headers param is missing`, headerKey)
	}
	return nil
}

// validateCoveredContentRequestTarget checks that an HTTP request has the necessary info to form the request target string.
// See https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
func (sp *SigParams) validateCoveredContentRequestTarget(req *http.Request) *codedError {
	m := strings.ToLower(req.Method)
	if !strIn(m, enumLoweredHTTPMethods[:]...) {
		return codedErrorf(errorCodeInvalidRequestTargetMethod, "invalid request target HTTP method: %q", req.Method)
	}
	if req.URL == nil || req.URL.RequestURI() == "" {
		return codedErrorf(errorCodeInvalidRequestTargetURI, "empty request target URI")
	}
	return nil
}

func (sp *SigParams) validateRequiredParams() *codedError {
	// Check required parameters. https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-4.1
	if sp.KeyID == "" {
		return newCodedError(errorCodeSigParamRequiredKeyID, `signature "keyId" parameter required`)
	}
	if sp.Signature == "" {
		return newCodedError(errorCodeSigParamRequiredSignature, `signature "signature" parameter required`)
	}
	return nil
}
