package signedhttpmessages

import (
	"fmt"
)

const (
	errorCodeZero = iota
	errorCodeInvalidRequestTargetMethod
	errorCodeInvalidRequestTargetURI

	// Signature Header parsing
	errorCodeSigHeaderParseDupeParamAlgorithm
	errorCodeSigHeaderParseDupeParamKeyID
	errorCodeSigHeaderParseDupeParamCreated
	errorCodeSigHeaderParseDupeParamExpires
	errorCodeSigHeaderParseDupeParamHeaders
	errorCodeSigHeaderParseDupeParamSignature
	errorCodeSigHeaderParseInvalidParam

	// Params validation.
	errorCodeSigParamInvalidAlgorithm
	// Required params missing. https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-4.1
	errorCodeSigParamRequiredKeyID
	errorCodeSigParamRequiredSignature
	// Headers param identifier issues.
	errorCodeSigParamHeadersIdentifiersDupe
	errorCodeSigParamHeadersIdentifiersCreatedInvalidAlgorithm // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
	errorCodeSigParamHeadersIdentifiersCreatedMissing          // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
	errorCodeSigParamHeadersIdentifiersExpiresInvalidAlgorithm // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
	errorCodeSigParamHeadersIdentifiersExpiresMissing          // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2
	errorCodeSigParamHeadersIdentifiersHeaderMissing           // https://tools.ietf.org/id/draft-ietf-httpbis-message-signatures-00.html#section-3.2.2

)

type codedError struct {
	Code int
	Msg  string
}

func (e *codedError) Error() string {
	return e.Msg
}

func codedErrorf(code int, format string, a ...interface{}) *codedError {
	return &codedError{Code: code, Msg: fmt.Sprintf(format, a...)}
}

func newCodedError(code int, text string) *codedError {
	return &codedError{Code: code, Msg: text}
}
