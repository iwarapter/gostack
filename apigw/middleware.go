package apigw

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
)

type contextKey string

const AuthorizerContext contextKey = "authorizer"

func (api *API) Authorizer(arn, authType string, h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		subl := log.With().Str("handler", "apigateway-authorizer").Logger()
		header := r.Header.Get("authorization")
		if header == "" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		auth, ok := api.authCache.Get(header)
		subl.Info().Bool("cache_hit", ok).Msg("checking authorizer cache")
		if ok { // we use a cached response, move on
			if isAuthResponseDeny(auth) {
				subl.Info().Bool("cache_hit", ok).Msg("policy deny")
				w.WriteHeader(http.StatusUnauthorized)
				return
			} else {
				subl.Info().Bool("cache_hit", ok).Msg("policy allow")
				h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthorizerContext, auth)))
				return
			}
		}
		var payload any
		switch strings.ToLower(authType) {
		case "token":
			payload = events.APIGatewayCustomAuthorizerRequest{
				Type:               "TOKEN",
				AuthorizationToken: header,
				MethodArn:          "some arn",
			}
		case "request":
			params := mux.Vars(r)

			headers := make(map[string]string)
			for key := range r.Header {
				headers[key] = r.Header.Get(key)
			}
			qParams := make(map[string]string)
			for k, v := range r.URL.Query() {
				qParams[k] = strings.Join(v, " ")
			}
			payload = events.APIGatewayProxyRequest{
				Resource:              "/{proxy+}",
				Path:                  strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/restapis/%s", api.ID)),
				HTTPMethod:            r.Method,
				QueryStringParameters: qParams,
				Headers:               headers,
				PathParameters:        params,
			}
		}
		authResponse, err := api.lambs.Invoke(arn, payload)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			subl.Error().Err(err).Str("arn", arn).Msg("unable to invoke authorizer")
			return
		}
		err = json.Unmarshal(authResponse, &auth)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		api.authCache.Set(header, auth, cache.WithExpiration(5*time.Minute))
		if isAuthResponseDeny(auth) {
			subl.Info().Msg("policy deny")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		subl.Info().Msg("policy allow")
		h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), AuthorizerContext, auth)))
	}
}

func isAuthResponseDeny(auth events.APIGatewayCustomAuthorizerResponse) bool {
	for _, statement := range auth.PolicyDocument.Statement {
		if strings.ToLower(statement.Effect) == "deny" {
			return true
		}
	}
	return false
}

func (api *API) LambdaProxy(arn, path, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := mux.Vars(r)

		headers := make(map[string]string)
		for key := range r.Header {
			headers[key] = r.Header.Get(key)
		}
		qParams := make(map[string]string)
		for k, v := range r.URL.Query() {
			qParams[k] = strings.Join(v, " ")
		}
		payload := events.APIGatewayProxyRequest{
			Resource:              "/{proxy+}",
			Path:                  strings.TrimPrefix(r.URL.Path, fmt.Sprintf("/restapis/%s", api.ID)),
			HTTPMethod:            method,
			QueryStringParameters: qParams,
			Headers:               headers,
			PathParameters:        params,
		}

		if auth := r.Context().Value(AuthorizerContext); auth != nil {
			payload.RequestContext = events.APIGatewayProxyRequestContext{
				Authorizer: auth.(events.APIGatewayCustomAuthorizerResponse).Context,
			}
		}
		b, err := api.lambs.Invoke(arn, payload)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var resp events.APIGatewayProxyResponse
		if err = json.Unmarshal(b, &resp); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		_, _ = w.Write([]byte(resp.Body))
	}
}

type detailedResponseWriter struct {
	http.ResponseWriter
	statusCode int
}

func (dw *detailedResponseWriter) WriteHeader(code int) {
	dw.statusCode = code
	dw.ResponseWriter.WriteHeader(code)
}

func (dw *detailedResponseWriter) StatusCode() int {
	return dw.statusCode
}

func Logger(next http.Handler, name string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		dw := &detailedResponseWriter{ResponseWriter: w}
		next.ServeHTTP(dw, r)
		log.Info().
			Str("name", name).
			Str("method", r.Method).
			Str("request_uri", r.URL.Path).
			Dur("duration", time.Since(start)).
			Int("status_code", dw.StatusCode()).
			Send()
	})
}
