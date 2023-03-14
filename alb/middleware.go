package alb

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-lambda-go/events"
	"github.com/rs/zerolog/log"
)

func FixedResponseHandler(body, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Content-Type", contentType)
		_, _ = w.Write([]byte(body))
		w.WriteHeader(http.StatusOK)
	}
}

func (alb *ALB) LambdaProxy(arn string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		headers := make(map[string]string)
		for key := range r.Header {
			headers[key] = r.Header.Get(key)
		}
		qParams := make(map[string]string)
		for k, v := range r.URL.Query() {
			qParams[k] = strings.Join(v, " ")
		}
		payload := events.ALBTargetGroupRequest{
			HTTPMethod:            r.Method,
			Path:                  r.URL.Path,
			Headers:               headers,
			QueryStringParameters: qParams,
		}
		b, err := alb.lambs.Invoke(arn, payload)
		if err != nil {
			log.Error().Err(err).Str("arn", arn).Msg("unable to invoke lambda")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		var resp events.ALBTargetGroupResponse
		if err = json.Unmarshal(b, &resp); err != nil {
			log.Error().Err(err).Str("arn", arn).Msg("unable to unmarshal lambda response")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		for k, v := range resp.Headers {
			w.Header().Set(k, v)
		}
		w.WriteHeader(resp.StatusCode)
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

func Logger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		dw := &detailedResponseWriter{ResponseWriter: w}
		next.ServeHTTP(dw, r)
		log.Info().
			Str("method", r.Method).
			Str("request_uri", r.URL.Path).
			Dur("duration", time.Since(start)).
			Int("status_code", dw.StatusCode()).
			Send()
	})
}
