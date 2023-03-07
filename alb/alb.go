package alb

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/iwarapter/gostack/config"
	"github.com/iwarapter/gostack/lambstack"

	"strings"
)

type ALB struct {
	signer   *ecdsa.PrivateKey
	lambs    lambstack.LambdaFactory
	router   *mux.Router
	mockData map[string]mockdata
}

type mockdata struct {
	Userinfo      string
	Token         string
	Introspection string
	OidcData      string
}

var store = sessions.NewCookieStore([]byte("top_secret"))

func New(subrouter *mux.Router, lambs lambstack.LambdaFactory) *ALB {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		panic("unable to marshall the public key")
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})

	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
		//SameSite: http.SameSiteNoneMode,
		//Secure:   false,
		//Domain: "alb.127.0.0.1.nip.io",
	}
	authRouter := subrouter.Host("auth.127.0.0.1.nip.io").Subrouter()
	albRouter := subrouter.Host("alb.127.0.0.1.nip.io").Subrouter()

	subrouter.Host("keys-alb.127.0.0.1.nip.io").Methods(http.MethodGet).Path("/fakekey").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, string(pub))
	})

	api := &ALB{
		signer:   key,
		router:   albRouter,
		lambs:    lambs,
		mockData: map[string]mockdata{},
	}

	authRouter.Methods(http.MethodPost).Path("/submit").Handler(api.authSubmitHandler())
	authRouter.Methods(http.MethodGet).Path("/login").Handler(api.authLoginHandler())
	authRouter.Methods(http.MethodGet).Path("/end").Handler(api.endSession())
	authRouter.Methods(http.MethodGet).Path("/userinfo").Handler(api.userinfo())
	authRouter.Methods(http.MethodPost).Path("/introspection").Handler(api.introspection())

	albRouter.Methods(http.MethodGet).Path("/oauth2/idpresponse").Handler(api.idpResponse())

	return api
}

func (alb *ALB) AddRule(rule config.ALBRule) error {
	var r *mux.Route

	if strings.HasSuffix(rule.Path, "/") {
		r = alb.router.PathPrefix(rule.Path)
	} else {
		r = alb.router.Path(rule.Path)
	}
	if len(rule.Methods) > 0 {
		r.Methods(rule.Methods...)
	}
	if rule.OIDC && rule.FixedResponse != nil {
		r.Handler(alb.OidcHandler(FixedResponseHandler(rule.FixedResponse.Body, rule.FixedResponse.ContentType)))
	}
	if !rule.OIDC && rule.FixedResponse != nil {
		r.Handler(FixedResponseHandler(rule.FixedResponse.Body, rule.FixedResponse.ContentType))
	}

	if rule.OIDC && rule.Target != "" {
		r.Handler(alb.OidcHandler(alb.LambdaProxy(rule.Target)))
	}
	if !rule.OIDC && rule.Target != "" {
		r.Handler(alb.LambdaProxy(rule.Target))
	}

	if rule.OIDC && rule.Files != nil {
		spa := spaHandler{staticPath: rule.Files.Path, indexPath: rule.Files.Index}
		r.Handler(alb.OidcHandler(spa.ServeHTTP))
	}
	if !rule.OIDC && rule.Files != nil {
		spa := spaHandler{staticPath: rule.Files.Path, indexPath: rule.Files.Index}
		r.Handler(spa)
	}
	return nil
}
