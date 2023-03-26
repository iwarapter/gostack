package alb

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

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
		body, err := io.ReadAll(r.Body)
		if err != nil {
			log.Error().Err(err).Str("arn", arn).Msg("unable to read body")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		defer r.Body.Close()
		payload := events.ALBTargetGroupRequest{
			HTTPMethod:            r.Method,
			Path:                  r.URL.Path,
			Headers:               headers,
			QueryStringParameters: qParams,
			Body:                  string(body),
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
		for hdr, vals := range resp.MultiValueHeaders {
			for _, val := range vals {
				w.Header().Add(hdr, val)
			}
		}
		for k, v := range resp.Headers {
			w.Header().Add(k, v)
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write([]byte(resp.Body))
	}
}
