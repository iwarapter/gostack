package alb

import (
	"crypto/ecdsa"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	mrand "math/rand"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"text/template"
	"time"

	cache "github.com/Code-Hex/go-generics-cache"

	"github.com/golang-jwt/jwt/v4"
	"github.com/rs/zerolog/log"
)

var loginForm = `
<!DOCTYPE html>
<html lang="en">

<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>GOSTACK Login</title>

  <style>
    body {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
      text-align: center;
      background: #121212;
      color: white;
    }

	pre {
	  color: orange;
	}

    button {
      background-color: #4CAF50;
      color: black;
      border: 2px solid #4CAF50;
      min-width: 100%;
      padding: .3rem;
    }

    label {
      text-align: initial;
    }

	input {
      font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
    }

    .form {
      display: inline-grid;
    }

    .submit {
      text-align: end;
    }
  </style>
</head>

<body>
  <form class="form" action="/submit" method="POST">
	<pre>
        ░██████╗░░█████╗░░██████╗████████╗░█████╗░░█████╗░██╗░░██╗      
        ██╔════╝░██╔══██╗██╔════╝╚══██╔══╝██╔══██╗██╔══██╗██║░██╔╝      
        ██║░░██╗░██║░░██║╚█████╗░░░░██║░░░███████║██║░░╚═╝█████═╝░      
        ██║░░╚██╗██║░░██║░╚═══██╗░░░██║░░░██╔══██║██║░░██╗██╔═██╗░      
        ╚██████╔╝╚█████╔╝██████╔╝░░░██║░░░██║░░██║╚█████╔╝██║░╚██╗      
        ░╚═════╝░░╚════╝░╚═════╝░░░░╚═╝░░░╚═╝░░╚═╝░╚════╝░╚═╝░░╚═╝      
	</pre>

    <label for="sub">SUB:</label>
    <input id="sub" name="sub" rows="1" cols="50" value="user@test.io">
    <br />

    <label for="introspection">INTROSPECTION:</label>
    <textarea id="introspection" rows="10" cols="50" name="introspection">%s</textarea>
    <br />

    <label for="userinfo">USERINFO:</label>
    <textarea id="userinfo" rows="10" cols="50" name="userinfo">%s</textarea>
    <br />

	<label for="cookie-max-age">Cookie Max-Age (Seconds):</label>
    <input id="cookie-max-age" rows="1" cols="50" name="cookie-max-age" value="300">
    <br />

    <div class="submit">
      <button type="submit">Submit</button>
    </div>
  </form>
</body>

</html>
`

func authLoginHandler(alb *ALB) http.HandlerFunc {
	// TODO this should be an actual template with values but I'm lazy
	tmpl := template.Must(template.New("login").Parse(fmt.Sprintf(loginForm, alb.conf.DefaultIntrospection, alb.conf.DefaultUserinfo)))
	return func(w http.ResponseWriter, r *http.Request) {
		if err := tmpl.Execute(w, ""); err != nil {
			log.Error().Err(err).Msg("unable to render auth login page")
		}
	}
}

func (alb *ALB) OidcHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		sess, _ := store.Get(r, "gostack")

		// Check if user is authenticated
		vals := sess.Values
		if _, ok := vals["authenticated"].(bool); !ok {
			// in a normal oidc flow you'd hit the authorization_endpoint here, but we are faking all of that
			http.Redirect(w, r, fmt.Sprintf("http://auth.127.0.0.1.nip.io:%d/login?redirect_uri=http://%s.127.0.0.1.nip.io:%d", alb.port, alb.name, alb.port), http.StatusFound)
			return
		}

		token := sess.Values["token"].(string)
		data := tokenData[token]
		oidcData, _ := alb.signJwt(oidcHeader(), data.Userinfo)

		r.Header.Set("x-amzn-oidc-accesstoken", token)
		r.Header.Set("x-amzn-oidc-data", oidcData)
		next.ServeHTTP(w, r)
	}
}

func (alb *ALB) signJwt(header, claims map[string]any) (string, error) {
	headerBytes, err := json.Marshal(header)
	if err != nil {
		return "", err
	}
	hdr := base64.URLEncoding.EncodeToString(headerBytes)
	claimsBytes, err := json.Marshal(claims)
	if err != nil {
		return "", err
	}
	clm := base64.URLEncoding.EncodeToString(claimsBytes)
	toSign := strings.Join([]string{hdr, clm}, ".")
	hasher := jwt.SigningMethodES256.Hash.New()
	hasher.Write([]byte(toSign))
	r, s, err := ecdsa.Sign(rand.Reader, key, hasher.Sum(nil))
	if err != nil {
		return "", err
	}
	curveBits := key.Curve.Params().BitSize

	keyBytes := curveBits / 8
	if curveBits%8 > 0 {
		keyBytes += 1
	}

	// We serialize the outputs (r and s) into big-endian byte arrays
	// padded with zeros on the left to make sure the sizes work out.
	// Output must be 2*keyBytes long.
	out := make([]byte, 2*keyBytes)
	r.FillBytes(out[0:keyBytes]) // r is assigned to the first half of output.
	s.FillBytes(out[keyBytes:])  // s is assigned to the second half of output.

	return strings.Join([]string{hdr, clm, base64.URLEncoding.EncodeToString(out)}, "."), nil
}

const alphaNumeric = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func createToken(n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphaNumeric[mrand.Intn(len(alphaNumeric))] //#nosec
	}
	return string(b)
}

func authSubmitHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		defer r.Body.Close()

		if !r.Form.Has("sub") {
			log.Error().Msg("the sub field is required to login")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		sub := r.Form.Get("sub")

		code := createToken(32)
		token := createToken(32)
		codeCache.Set(code, token, cache.WithExpiration(1*time.Minute))

		intro := make(map[string]any)
		_ = json.Unmarshal([]byte(r.Form.Get("introspection")), &intro)
		intro["sub"] = sub
		introResp, _ := json.Marshal(intro)

		claims := make(map[string]any)
		_ = json.Unmarshal([]byte(r.Form.Get("userinfo")), &claims)
		claims["sub"] = sub

		maxAge, err := strconv.Atoi(r.Form.Get("cookie-max-age"))
		if err != nil {
			log.Error().Err(err).Msg("unable to parse cookie max age")
			maxAge = 300
		}
		referer := r.Header.Get("Referer")
		u, err := url.Parse(referer)
		if err != nil {
			log.Error().Err(err).Msg("unable to parse referer")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		redirectURI := u.Query().Get("redirect_uri")
		tokenData[token] = mockdata{
			Sub:           sub,
			Userinfo:      claims,
			Introspection: string(introResp),
			CookieMaxAge:  &maxAge,
		}
		http.Redirect(w, r, fmt.Sprintf("%s/oauth2/idpresponse?code=%s", redirectURI, code), http.StatusFound)
	}
}

func oidcHeader() map[string]any {
	return map[string]interface{}{
		"alg":    "ES256",
		"client": "some-oidc-client",
		"exp":    float64(time.Now().Add(5 * time.Minute).Unix()),
		"iss":    "http://fake.alb.io",
		"kid":    "fakekey",
		"signer": "arn:aws:elasticloadbalancing:eu-west-2:12345678901:loadbalancer/app/demo/d3e0e00f95dd5ef4",
		"typ":    "JWT",
	}
}

func (alb *ALB) idpResponse() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		token, ok := codeCache.Get(code)
		if !ok {
			log.Error().Str("code", code).Msg("unable to find code to exchange, redirecting to login")
			http.Redirect(w, r, fmt.Sprintf("http://auth.127.0.0.1.nip.io:%d/login", alb.port), http.StatusFound)
			return
		}
		var data mockdata
		if data, ok = tokenData[token]; !ok {
			log.Error().Str("token", token).Msg("unable to find token data")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		sess, _ := store.Get(r, "gostack")
		sess.Values["authenticated"] = true
		sess.Values["sub"] = data.Sub
		sess.Values["token"] = token
		if data.CookieMaxAge != nil {
			sess.Options.MaxAge = *data.CookieMaxAge
		}
		if err := sess.Save(r, w); err != nil {
			log.Error().Err(err).Msg("unable to save session for idp response")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		http.Redirect(w, r, fmt.Sprintf("http://%s.127.0.0.1.nip.io:%d/", alb.name, alb.port), http.StatusFound)
		w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
		w.Header().Set("Content-Type", "text/html")
	}
}

func endSession() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		params := r.URL.Query()
		postLogoutRedirectURI := params.Get("post_logout_redirect_uri")
		if postLogoutRedirectURI != "" {
			http.Redirect(w, r, postLogoutRedirectURI, http.StatusFound)
			return
		} else {
			log.Error().Msg("no 'post_logout_redirect_uri' query param provided for the end session endpoint")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
	}
}

func userinfo() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if token, err := getTokenFromHeader(r.Header); err != nil {
			w.WriteHeader(http.StatusUnauthorized)
		} else {
			if data, ok := tokenData[token]; ok {
				w.Header().Set("Content-Type", "application/json")
				b, _ := json.Marshal(data.Userinfo)
				_, _ = w.Write(b)
			} else {
				log.Error().Str("token", token).Msg("the token is not in the mock data store")
				w.WriteHeader(http.StatusBadRequest)
			}
		}
	}
}

func getTokenFromHeader(headers map[string][]string) (string, error) {
	auth := headers["Authorization"]
	if len(auth) == 0 {
		return "", fmt.Errorf("no authorization header provided")
	}
	if auth[0] == "" {
		auth = headers["authorization"]
	}
	rx := regexp.MustCompile(`^[bB]earer (.*)$`)
	token := rx.FindStringSubmatch(auth[0])
	if len(token) != 2 {
		return "", fmt.Errorf("unable to extract bearer token from header")
	}
	return token[1], nil
}

func introspection() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		// TODO it should be authenticated
		if token := r.Form.Get("token"); token != "" {
			if data, ok := tokenData[token]; ok {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write([]byte(data.Introspection))
				return
			} else {
				log.Error().Str("token", token).Msg("the token is not in the mock data store")
			}
		} else {
			log.Error().Msg("token must be in the form body for introspection requests")
		}
		w.Header().Set("Content-Type", "application/json; charset=UTF-8")
		_, _ = w.Write([]byte(`{"active":false}`))
	}
}
