package gqlgensignedops

import (
	"context"
	"slices"

	"github.com/99designs/gqlgen/graphql"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

// WithParseOption returns a [NewOption] that appends opts to the [jwt.ParseOption]
// values used when parsing the signature token.
func WithParseOption(opts ...jwt.ParseOption) NewOption {
	return &optWithParseOption{opts: opts}
}

type optWithParseOption struct{ opts []jwt.ParseOption }

func (o *optWithParseOption) applyNewOption(ext *Extension) {
	ext.parseOptions = append(ext.parseOptions, o.opts...)
}

// NewOption configures an [Extension].
type NewOption interface {
	applyNewOption(ext *Extension)
}

// New creates an [Extension] configured with opts.
func New(opts ...NewOption) *Extension {
	ext := &Extension{}
	for _, o := range opts {
		o.applyNewOption(ext)
	}
	return ext
}

// Extension is a [graphql.HandlerExtension] that verifies an incoming operation's
// query against a document claim embedded in a signed JWT.
type Extension struct {
	parseOptions []jwt.ParseOption
}

var (
	_ graphql.HandlerExtension          = (*Extension)(nil)
	_ graphql.OperationParameterMutator = (*Extension)(nil)
)

func (Extension) ExtensionName() string { return "github.com/aereal/gqlgen-signedops.Extension" }

func (Extension) Validate(graphql.ExecutableSchema) error { return nil }

func (ext *Extension) MutateOperationParameters(ctx context.Context, request *graphql.RawParams) *gqlerror.Error {
	sig, err := extractSignature(request)
	if err != nil {
		return gqlerror.Wrap(err)
	}
	parseOptions := slices.Clone(ext.parseOptions)
	parseOptions = append(parseOptions, jwt.WithRequiredClaim(claimDocument))
	tok, err := jwt.ParseString(sig, parseOptions...)
	if err != nil {
		return gqlerror.Wrap(err)
	}
	doc, err := getDocument(tok)
	if err != nil {
		return gqlerror.Wrap(err)
	}
	if request.Query != doc {
		return gqlerror.Wrap(ErrQuerySignatureMismatch)
	}
	return nil
}

func extractSignature(r *graphql.RawParams) (string, error) {
	raw, ok := r.Extensions[extField]
	if !ok {
		return "", ErrRequestHasNoSignature
	}
	sig, ok := raw.(string)
	if !ok {
		return "", ErrInvalidSignatureType
	}
	return sig, nil
}

func getDocument(t jwt.Token) (string, error) { return jwt.Get[string](t, claimDocument) }

const (
	extField      = "github.com/aereal/graphql-signedops"
	claimDocument = "document"
)
