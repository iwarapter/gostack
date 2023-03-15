package alb

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"

	cache "github.com/Code-Hex/go-generics-cache"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/iwarapter/gostack/config"
	"github.com/iwarapter/gostack/lambstack"

	"strings"
)

type ALB struct {
	signer       *ecdsa.PrivateKey
	lambs        lambstack.LambdaFactory
	router       *mux.Router
	mockData     map[string]mockdata
	codeExchange *cache.Cache[string, string]
}

type mockdata struct {
	Userinfo      string
	Sub           string
	Introspection string
	OidcData      string
}

var store = sessions.NewCookieStore([]byte("top_secret"))

func New(subrouter *mux.Router, lambs lambstack.LambdaFactory, mdata map[string]config.MockData) *ALB {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
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
	}
	authRouter := subrouter.Host("auth.127.0.0.1.nip.io").Subrouter()
	albRouter := subrouter.Host("alb.127.0.0.1.nip.io").Subrouter()

	subrouter.Host("keys-alb.127.0.0.1.nip.io").Methods(http.MethodGet).Path("/fakekey").HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, string(pub))
	})

	lb := &ALB{
		signer:       key,
		router:       albRouter,
		lambs:        lambs,
		mockData:     map[string]mockdata{},
		codeExchange: cache.NewContext[string, string](ctx),
	}
	for s, dat := range mdata {
		intro, _ := json.Marshal(dat.Introspection)
		uinfo, _ := json.Marshal(dat.Userinfo)
		lb.mockData[s] = mockdata{Introspection: string(intro), Userinfo: string(uinfo)}
	}

	authRouter.Methods(http.MethodPost).Path("/submit").Handler(lb.authSubmitHandler())
	authRouter.Methods(http.MethodGet).Path("/login").Handler(lb.authLoginHandler())
	authRouter.Methods(http.MethodGet).Path("/end").Handler(lb.endSession())
	authRouter.Methods(http.MethodGet).Path("/userinfo").Handler(lb.userinfo())
	authRouter.Methods(http.MethodPost).Path("/introspection").Handler(lb.introspection())

	albRouter.Methods(http.MethodGet).Path("/oauth2/idpresponse").Handler(lb.idpResponse())

	return lb
}

func (alb *ALB) AddRule(rule config.ALBRule) error {
	var r *mux.Route

	if strings.HasSuffix(rule.Path, "/") {
		r = alb.router.PathPrefix(rule.Path)
	} else {
		r = alb.router.Path(rule.Path)
	}
	for key, value := range rule.Headers {
		r.Headers(key, value)
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
