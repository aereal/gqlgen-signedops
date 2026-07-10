package gqlgensignedops

var ErrRequestHasNoSignature RequestHasNoSignatureError

// RequestHasNoSignatureError indicates that a request's extensions do not
// contain a signature.
type RequestHasNoSignatureError struct{}

var _ error = RequestHasNoSignatureError{}

func (RequestHasNoSignatureError) Error() string { return "request has no signature" }

var ErrInvalidSignatureType InvalidSignatureTypeError

// InvalidSignatureTypeError indicates that a request's signature extension
// value is not a string.
type InvalidSignatureTypeError struct{}

var _ error = InvalidSignatureTypeError{}

func (InvalidSignatureTypeError) Error() string { return "invalid signature type" }

var ErrQuerySignatureMismatch QuerySignatureMismatchError

// QuerySignatureMismatchError indicates that the document claim in the
// signature does not match the request's query.
type QuerySignatureMismatchError struct{}

var _ error = QuerySignatureMismatchError{}

func (QuerySignatureMismatchError) Error() string { return "query signature mismatch" }
