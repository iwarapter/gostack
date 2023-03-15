package apigw

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/mux"
	"github.com/iwarapter/gostack/lambstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type mockFactory struct {
	lambstack.LambdaFactory
	responses map[string]func(payload any) ([]byte, error)
}

func (m mockFactory) Invoke(arn string, payload any) ([]byte, error) {
	return m.responses[arn](payload)
}

func Test_ImportSimpleGetAPI(t *testing.T) {
	f := &mockFactory{
		responses: map[string]func(payload any) ([]byte, error){
			"arn:aws:lambda:us-east-1:123456789012:function:simple": func(_ any) ([]byte, error) {
				resp := events.APIGatewayProxyResponse{
					Body:       "unit-test",
					StatusCode: http.StatusOK,
				}

				return json.Marshal(&resp)
			},
		},
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("examples/simple.yml")
	require.NoError(t, err)
	require.NoError(t, doc.Validate(context.Background()))

	r := mux.NewRouter().Host("api.127.0.0.1.nip.io").Subrouter()
	api := New(r, f, "unit-test")
	require.NoError(t, api.Import(doc))

	rt := r.Get("getExample")
	assert.NotNil(t, rt)
	methods, _ := rt.GetMethods()
	host, _ := rt.GetHostTemplate()
	path, _ := rt.GetPathTemplate()
	assert.Equal(t, []string{"GET"}, methods)
	assert.Equal(t, "api.127.0.0.1.nip.io", host)
	assert.Equal(t, "/unit-test/simple", path)
	srv := httptest.NewServer(r)
	cli := srv.Client()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("%s/unit-test/simple", srv.URL), nil)
	require.NoError(t, err)
	req.Host = "api.127.0.0.1.nip.io"
	resp, err := cli.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("unit-test"), b)
}

func Test_ImportLambdaAuthorizerGetAPI(t *testing.T) {
	calls := 0
	f := &mockFactory{
		responses: map[string]func(payload any) ([]byte, error){
			"arn:aws:lambda:us-east-1:123456789012:function:simple": func(_ any) ([]byte, error) {
				resp := events.APIGatewayProxyResponse{
					Body:       "unit-test",
					StatusCode: http.StatusOK,
				}
				calls++
				return json.Marshal(&resp)
			},
			"arn:aws:lambda:us-east-1:123456789012:function:request-auth": func(_ any) ([]byte, error) {
				resp := events.APIGatewayCustomAuthorizerResponse{
					PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{
						Statement: []events.IAMPolicyStatement{
							{
								Action:   []string{"*"},
								Effect:   "Allow",
								Resource: []string{"my-resource"},
							},
						},
					},
					Context: map[string]interface{}{},
				}
				calls++
				return json.Marshal(&resp)
			},
		},
	}

	loader := openapi3.NewLoader()
	doc, err := loader.LoadFromFile("examples/lambda-authorizer.yml")
	require.NoError(t, err)
	require.NoError(t, doc.Validate(context.Background()))

	r := mux.NewRouter().Host("api.127.0.0.1.nip.io").Subrouter()
	api := New(r, f, "unit-test")
	require.NoError(t, api.Import(doc))

	rt := r.Get("getExample")
	assert.NotNil(t, rt)
	methods, _ := rt.GetMethods()
	host, _ := rt.GetHostTemplate()
	path, _ := rt.GetPathTemplate()
	assert.Equal(t, []string{"GET"}, methods)
	assert.Equal(t, "api.127.0.0.1.nip.io", host)
	assert.Equal(t, "/unit-test/simple", path)
	srv := httptest.NewServer(r)
	cli := srv.Client()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, fmt.Sprintf("%s/unit-test/simple", srv.URL), nil)
	require.NoError(t, err)
	req.Host = "api.127.0.0.1.nip.io"
	req.Header.Set("Authorization", "fake")
	resp, err := cli.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	assert.Equal(t, []byte("unit-test"), b)
	assert.Equal(t, 2, calls)
}
