package alb

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestALB_OidcHandler(t *testing.T) {}

func TestALB_authLoginHandler(t *testing.T) {}

func TestALB_authSubmitHandler(t *testing.T) {}

func TestALB_endSession(t *testing.T) {}

func TestALB_idpResponse(t *testing.T) {
	alb := &ALB{
		name: "unit-test",
		port: 8080,
	}
	codeCache.Set("my-example-code", "my-example-token")
	tokenData["my-example-token"] = mockdata{
		Userinfo:      map[string]any{"sub": "my-sub"},
		Sub:           "my-sub",
		Introspection: `{"active":true}`,
		CookieMaxAge:  nil,
	}
	tests := []struct {
		name     string
		req      *http.Request
		validate func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "unknown tokens get appropriate response",
			req:  httptest.NewRequest(http.MethodGet, "/idpresponse?code=unknown-code", nil),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusFound, recorder.Code)
				require.Equal(t, "http://auth.127.0.0.1.nip.io:8080/login", recorder.Header().Get("Location"))
			},
		},
		{
			name: "known tokens get appropriate response",
			req:  httptest.NewRequest(http.MethodGet, "/?code=my-example-code", nil),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusFound, recorder.Code)
				require.Equal(t, "http://unit-test.127.0.0.1.nip.io:8080/", recorder.Header().Get("Location"))
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			alb.idpResponse().ServeHTTP(rec, tt.req)
			tt.validate(t, rec)
		})
	}
}

func TestALB_introspection(t *testing.T) {
	tokenData["my-example-token"] = mockdata{Introspection: `{"active":true}`}
	tests := []struct {
		name     string
		req      *http.Request
		validate func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "unknown tokens get appropriate response",
			req:  tokenRequest(t, "unknown-token"),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Equal(t, `{"active":false}`, recorder.Body.String())
			},
		},
		{
			name: "known tokens get appropriate response",
			req:  tokenRequest(t, "my-example-token"),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Equal(t, `{"active":true}`, recorder.Body.String())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			introspection().ServeHTTP(rec, tt.req)
			tt.validate(t, rec)
		})
	}
}

func tokenRequest(t *testing.T, token string) *http.Request {
	form := url.Values{}
	form.Add("token", token)
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/introspection", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func TestALB_signJwt(t *testing.T) {}

func TestALB_userinfo(t *testing.T) {}

func Test_createToken(t *testing.T) {}

func Test_getTokenFromHeader(t *testing.T) {}

func Test_oidcHeader(t *testing.T) {}
