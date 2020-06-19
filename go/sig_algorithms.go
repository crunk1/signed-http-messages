// https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#name-http-signature-algorithms-r
package signedhttpmessages

import (
	"crypto/hmac"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"hash"
)

type Algorithm string

const (
	HS2019      Algorithm = "hs2019"
	RSASHA1     Algorithm = "rsa-sha1"
	RSASHA256   Algorithm = "rsa-sha256"
	HMACSHA256  Algorithm = "hmac-sha256"
	ECDSASHA256 Algorithm = "ecdsa-sha256"
)

var allAlgorithms = []Algorithm{HS2019, RSASHA1, RSASHA256, HMACSHA256, ECDSASHA256}
var allAlgorithmStrs = []string{string(HS2019), string(RSASHA1), string(RSASHA256), string(HMACSHA256), string(ECDSASHA256)}
var deprecatedAlgorithms = []Algorithm{RSASHA1, RSASHA256, HMACSHA256, ECDSASHA256}

func (a Algorithm) isDeprecated() bool {
	for _, elem := range deprecatedAlgorithms {
		if a == elem {
			return true
		}
	}
	return false
}

func (a Algorithm) isValid() bool {
	for _, elem := range allAlgorithms {
		if a == elem {
			return true
		}
	}
	return false
}

func (a Algorithm) sign(key []byte, sigInput []byte) ([]byte, *codedError) {
	if a.isDeprecated() {
		fmt.Printf("WARNING algorithm %q marked as deprecated\n", a)
	}

	var h hash.Hash
	var signFn func(key []byte, sum []byte) ([]byte, *codedError)

	switch a {
	case ECDSASHA256:
		h = sha256.New()
		signFn = a.signECDSA
	case HMACSHA256:
		h = hmac.New(sha256.New, key)
	case HS2019:
		return nil, newCodedError(0, "hs2019 not implemented")
	case RSASHA1:
		h = sha1.New()
		signFn = a.signRSA
	case RSASHA256:
		h = sha256.New()
		signFn = a.signRSA
	default:
		return nil, codedErrorf(0, "unknown/unsupported signing algorithm: %q", a)
	}

	if _, err := h.Write(sigInput); err != nil {
		return nil, newCodedError(errorCodeZero, err.Error())
	}
	sum := h.Sum(nil)
	if signFn == nil {
		return sum, nil
	}
	return signFn(key, sum)
}

func (a Algorithm) signECDSA(key []byte, sum []byte) ([]byte, *codedError) {
	return nil, newCodedError(0, "signECDSA not implemented")
}

func (a Algorithm) signRSA(key []byte, sum []byte) ([]byte, *codedError) {
	return nil, newCodedError(0, "signRSA not implemented")
}

func (a Algorithm) verify(key []byte, sig []byte) *codedError {
	return nil
}
