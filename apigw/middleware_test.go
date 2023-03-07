package apigw

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/aws/aws-lambda-go/events"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func echo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`OK!`))
	}
}

func TestAPI_Authorizer(t *testing.T) {
	var requestAuthAllowCalls, requestAuthDenyCalls, tokenAuthAllowCalls int
	f := &mockFactory{
		responses: map[string]func() ([]byte, error){
			"arn:aws:lambda:us-east-1:123456789012:function:request-auth-allow": func() ([]byte, error) {
				resp := events.APIGatewayCustomAuthorizerResponse{PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{Statement: []events.IAMPolicyStatement{{Action: []string{"*"}, Effect: "Allow", Resource: []string{"my-resource"}}}}, Context: map[string]interface{}{}}
				requestAuthAllowCalls++
				return json.Marshal(&resp)
			},
			"arn:aws:lambda:us-east-1:123456789012:function:token-auth-allow": func() ([]byte, error) {
				resp := events.APIGatewayCustomAuthorizerResponse{PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{Statement: []events.IAMPolicyStatement{{Action: []string{"*"}, Effect: "Allow", Resource: []string{"my-resource"}}}}, Context: map[string]interface{}{}}
				tokenAuthAllowCalls++
				return json.Marshal(&resp)
			},
			"arn:aws:lambda:us-east-1:123456789012:function:request-auth-deny": func() ([]byte, error) {
				resp := events.APIGatewayCustomAuthorizerResponse{PolicyDocument: events.APIGatewayCustomAuthorizerPolicy{Statement: []events.IAMPolicyStatement{{Action: []string{"*"}, Effect: "Deny", Resource: []string{"my-resource"}}}}, Context: map[string]interface{}{}}
				requestAuthDenyCalls++
				return json.Marshal(&resp)
			},
		},
	}
	r := mux.NewRouter()
	api := New(r, f, "unit-test")

	tests := []struct {
		name, arn, authType string
		req                 *http.Request
		validate            func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "un-authenticated requests are rejected",
			req:  unauthenticatedGET(t),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
			},
		},
		{
			name:     "authenticated requests are allowed",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:request-auth-allow",
			authType: "request",
			req:      authenticatedGET(t, "allow"),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, []byte(`OK!`), rec.Body.Bytes())
				assert.Equal(t, 1, requestAuthAllowCalls)
			},
		},
		{
			name:     "repeat authenticated requests are allowed and cached",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:request-auth-allow",
			authType: "request",
			req:      authenticatedGET(t, "allow"),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, []byte(`OK!`), rec.Body.Bytes())
				assert.Equal(t, 1, requestAuthAllowCalls)
			},
		},
		{
			name:     "auth-deny requests are not allowed and cached",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:request-auth-deny",
			authType: "request",
			req:      authenticatedGET(t, "deny"),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Equal(t, 1, requestAuthDenyCalls)
			},
		},
		{
			name:     "repeat auth-deny requests are not allowed and cached",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:request-auth-deny",
			authType: "request",
			req:      authenticatedGET(t, "deny"),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusUnauthorized, rec.Code)
				assert.Equal(t, 1, requestAuthDenyCalls)
			},
		},

		{
			name:     "token auth requests are allowed",
			arn:      "arn:aws:lambda:us-east-1:123456789012:function:token-auth-allow",
			authType: "token",
			req:      authenticatedGET(t, "token"),
			validate: func(t *testing.T, rec *httptest.ResponseRecorder) {
				assert.Equal(t, http.StatusOK, rec.Code)
				assert.Equal(t, 1, tokenAuthAllowCalls)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			api.Authorizer(tt.arn, tt.authType, echo()).ServeHTTP(rec, tt.req)
			tt.validate(t, rec)
		})
	}
}

func unauthenticatedGET(t *testing.T) *http.Request {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	require.NoError(t, err)
	return req
}

func authenticatedGET(t *testing.T, authHeader string) *http.Request {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "/test", nil)
	require.NoError(t, err)
	req.Header.Add("Authorization", authHeader)
	return req
}
