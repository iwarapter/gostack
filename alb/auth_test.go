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

func TestALB_idpResponse(t *testing.T) {}

func TestALB_introspection(t *testing.T) {
	alb := ALB{
		mockData: map[string]mockdata{
			"my-example-token": {Introspection: `{"active":true}`},
		},
	}
	tests := []struct {
		name     string
		req      *http.Request
		validate func(*testing.T, *httptest.ResponseRecorder)
	}{
		{
			name: "unknown tokens get appropriate response",
			req:  unknownToken(t),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Equal(t, `{"active":false}`, recorder.Body.String())
			},
		},
		{
			name: "known tokens get appropriate response",
			req:  knownToken(t),
			validate: func(t *testing.T, recorder *httptest.ResponseRecorder) {
				require.Equal(t, http.StatusOK, recorder.Code)
				require.Equal(t, `{"active":true}`, recorder.Body.String())
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec := httptest.NewRecorder()
			alb.introspection().ServeHTTP(rec, tt.req)
			tt.validate(t, rec)
		})
	}
}

func unknownToken(t *testing.T) *http.Request {
	form := url.Values{}
	form.Add("token", "unknown")
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, "/introspection", strings.NewReader(form.Encode()))
	require.NoError(t, err)
	req.Header.Add("Content-Type", "application/x-www-form-urlencoded")
	return req
}

func knownToken(t *testing.T) *http.Request {
	form := url.Values{}
	form.Add("token", "my-example-token")
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
