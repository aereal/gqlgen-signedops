package gqlgensignedops_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/99designs/gqlgen/graphql"
	"github.com/99designs/gqlgen/graphql/handler"
	"github.com/99designs/gqlgen/graphql/handler/transport"
	gqlgensignedops "github.com/aereal/gqlgen-signedops"
	"github.com/google/go-cmp/cmp"
	"github.com/lestrrat-go/jwx/v4/jwa"
	"github.com/lestrrat-go/jwx/v4/jwt"
	"github.com/vektah/gqlparser/v2"
	"github.com/vektah/gqlparser/v2/ast"
	"github.com/vektah/gqlparser/v2/gqlerror"
)

const (
	sig         = `eyJhbGciOiJIUzI1NiJ9.eyJkb2N1bWVudCI6InF1ZXJ5IGdldE1lIHtcbiAgbWUge1xuICAgIG5hbWVcbiAgICBhZ2VcbiAgfVxufSJ9.SMUKQ7Mt2ReDEq5tl1pTc0GWHq7zwKsP0vkxojqBPvE`
	queryMyName = "query getMe {\n  me {\n    name\n  }\n}"
	queryMyAge  = "query getMe {\n  me {\n    name\n    age\n  }\n}"
)

func TestExtension(t *testing.T) {
	t.Parallel()

	gh, err := buildHandler()
	if err != nil {
		t.Fatal(err)
	}
	ext := gqlgensignedops.New(gqlgensignedops.WithParseOption(jwt.WithKey(jwa.HS256(), []byte(`cc7e0d44fd473002f1c42167459001140ec6389b7353f8088f4d9a95f2f596f2`))))
	gh.Use(ext)
	srv := httptest.NewServer(gh)
	t.Cleanup(srv.Close)

	testCases := []struct {
		*testCase
		name string
	}{
		{
			name: "ok: signature is verified",
			testCase: &testCase{
				params: &graphql.RawParams{
					Query:      queryMyAge,
					Extensions: map[string]any{"github.com/aereal/graphql-signedops": sig},
				},
				want: &graphql.Response{
					Data: mustEncode(json.Marshal(map[string]any{"me": map[string]any{"name": "Yuno", "age": 16}})),
				},
			},
		},
		{
			name: "query mismatc",
			testCase: &testCase{
				params: &graphql.RawParams{
					Query:      queryMyName,
					Extensions: map[string]any{"github.com/aereal/graphql-signedops": sig},
				},
				want: &graphql.Response{
					Data: json.RawMessage(`null`),
					Errors: gqlerror.List{
						gqlerror.Errorf("%s", gqlgensignedops.ErrQuerySignatureMismatch),
					},
				},
			},
		},
		{
			name: "invalid signature type",
			testCase: &testCase{
				params: &graphql.RawParams{
					Query:      queryMyAge,
					Extensions: map[string]any{"github.com/aereal/graphql-signedops": 0},
				},
				want: &graphql.Response{
					Data: json.RawMessage(`null`),
					Errors: gqlerror.List{
						gqlerror.Errorf("%s", gqlgensignedops.ErrInvalidSignatureType),
					},
				},
			},
		},
		{
			name: "no signature",
			testCase: &testCase{
				params: &graphql.RawParams{
					Query: queryMyAge,
				},
				want: &graphql.Response{
					Data: json.RawMessage(`null`),
					Errors: gqlerror.List{
						gqlerror.Errorf("%s", gqlgensignedops.ErrRequestHasNoSignature),
					},
				},
			},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			assertsResponse(t, srv.URL, tc.testCase)
		})
	}
}

type testCase struct {
	params *graphql.RawParams
	want   *graphql.Response
}

var schemaSrc = &ast.Source{
	Name: "schema.gql",
	Input: `
	type User {
		name: String!
		age: Int!
	}

	type Query {
		me: User
	}
	`,
}

var loadSchemaWithCache = sync.OnceValues(func() (*ast.Schema, error) {
	return gqlparser.LoadSchema(schemaSrc)
})

func buildHandler() (*handler.Server, error) {
	schema, err := loadSchemaWithCache()
	if err != nil {
		return nil, err
	}
	es := &graphql.ExecutableSchemaMock{
		SchemaFunc: func() *ast.Schema { return schema },
		ExecFunc: func(_ context.Context) graphql.ResponseHandler {
			return func(_ context.Context) *graphql.Response {
				return &graphql.Response{
					Data: json.RawMessage(`{"me":{"name":"Yuno","age":16}}`),
				}
			}
		},
	}
	h := handler.New(es)
	h.AddTransport(transport.POST{})
	return h, nil
}

func doRequest(ctx context.Context, url string, params *graphql.RawParams) (*graphql.Response, error) {
	buf := new(bytes.Buffer)
	if err := json.NewEncoder(buf).Encode(params); err != nil {
		return nil, fmt.Errorf("json.Encoder.Encode: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, buf)
	if err != nil {
		return nil, fmt.Errorf("http.NewRequestWithContext: %w", err)
	}
	req.Header.Set("content-type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http.Client.Do: %w", err)
	}
	defer resp.Body.Close()
	var body graphql.Response
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, fmt.Errorf("json.Decoder.Decode: %w", err)
	}
	return &body, nil
}

func assertsResponse(t *testing.T, endpoint string, tc *testCase) {
	t.Helper()
	body, err := doRequest(t.Context(), endpoint, tc.params)
	if err != nil {
		t.Fatal(err)
	}
	if diff := cmp.Diff(tc.want, body, optTransformResponseData); diff != "" {
		t.Errorf("body (-want, +got):\n%s", diff)
	}
}

func mustEncode(b []byte, err error) []byte {
	if err != nil {
		panic(err)
	}
	return b
}

var optTransformResponseData = cmp.FilterPath(
	func(p cmp.Path) bool {
		parent, edge := p.Index(-2), p.Index(-1)
		field, ok := edge.(cmp.StructField)
		if !ok {
			return false
		}
		return parent.Type().String() == "graphql.Response" && field.Name() == "Data"
	},
	cmp.Transformer("JSONRawMessage", func(msg json.RawMessage) map[string]any {
		m := make(map[string]any)
		if err := json.Unmarshal(msg, &m); err != nil {
			panic(err)
		}
		return m
	}))
