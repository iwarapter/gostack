package mw

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestXForwardedFor(t *testing.T) {
	tests := []struct {
		name     string
		headers  map[string]string
		expected string
	}{
		{
			name:     "no headers",
			expected: "127.0.0.1",
		},
		{
			name: "x-forwarded-for is chained",
			headers: map[string]string{
				"X-Forwarded-For": "127.0.0.1",
			},
			expected: "127.0.0.1, 127.0.0.1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := httptest.NewServer(XForwardedFor(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(r.Header.Get("X-Forwarded-For")))
			})))

			r, err := http.NewRequestWithContext(context.TODO(), http.MethodGet, srv.URL, nil)
			require.NoError(t, err)
			for k, v := range tt.headers {
				r.Header.Set(k, v)
			}
			resp, err := srv.Client().Do(r)
			require.NoError(t, err)
			defer resp.Body.Close()
			require.Equal(t, http.StatusOK, resp.StatusCode)
			b, err := io.ReadAll(resp.Body)
			require.NoError(t, err)
			require.Equal(t, tt.expected, string(b))
		})
	}
}
