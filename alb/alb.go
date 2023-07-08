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
	"net/http/httputil"
	"net/url"

	cache "github.com/Code-Hex/go-generics-cache"

	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"github.com/iwarapter/gostack/config"
	"github.com/iwarapter/gostack/lambstack"

	"strings"
)

type ALB struct {
	lambs  lambstack.LambdaFactory
	router *mux.Router
	name   string
	port   int
	conf   config.ALB
}

type mockdata struct {
	Userinfo      map[string]any
	Sub           string
	Introspection string
	CookieMaxAge  *int
}

var store = sessions.NewCookieStore([]byte("top_secret"))
var codeCache *cache.Cache[string, string]
var tokenData = map[string]mockdata{}
var key *ecdsa.PrivateKey
var keyFunc http.Handler

func init() {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	codeCache = cache.NewContext[string, string](ctx)
	store.Options = &sessions.Options{
		Path:     "/",
		MaxAge:   300,
		HttpOnly: true,
	}
	var err error
	key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}

	pubBytes, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		panic("unable to marshall the public key")
	}
	pub := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubBytes,
	})
	keyFunc = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprint(w, string(pub))
	})
}

func New(subrouter *mux.Router, lambs lambstack.LambdaFactory, conf config.ALB, stack config.GoStack, port int) *ALB {
	name := conf.Name
	if name == "" {
		name = "alb"
	}
	hostname := fmt.Sprintf("%s.127.0.0.1.nip.io", name)
	keysHostname := fmt.Sprintf("keys-%s.127.0.0.1.nip.io", name)
	albRouter := subrouter.Host(hostname).Subrouter()

	subrouter.Host(keysHostname).Methods(http.MethodGet).Path("/fakekey").Handler(keyFunc)

	if conf.DefaultUserinfo == "" {
		conf.DefaultUserinfo = "{}"
	}
	if conf.DefaultIntrospection == "" {
		conf.DefaultIntrospection = `{"active": true,"scope": "openid"}`
	}

	lb := &ALB{
		name:   name,
		router: albRouter,
		lambs:  lambs,
		port:   port,
		conf:   conf,
	}
	for s, dat := range stack.MockData {
		intro, _ := json.Marshal(dat.Introspection)
		tokenData[s] = mockdata{Introspection: string(intro), Userinfo: dat.Userinfo}
	}

	albRouter.Methods(http.MethodGet).Path("/oauth2/idpresponse").Handler(lb.idpResponse())
	authRouter := subrouter.Host("auth.127.0.0.1.nip.io").Subrouter()
	authRouter.Methods(http.MethodPost).Path("/submit").Handler(authSubmitHandler())
	authRouter.Methods(http.MethodGet).Path("/login").Handler(authLoginHandler(lb))
	authRouter.Methods(http.MethodGet).Path("/end").Handler(endSession())
	authRouter.Methods(http.MethodGet).Path("/userinfo").Handler(userinfo())
	authRouter.Methods(http.MethodPost).Path("/introspection").Handler(introspection())
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
		spa := spaHandler{staticPath: rule.Files.Path, indexPath: rule.Files.Index, responseHeaders: rule.Files.ResponseHeaders}
		r.Handler(alb.OidcHandler(spa.ServeHTTP))
	}
	if !rule.OIDC && rule.Files != nil {
		spa := spaHandler{staticPath: rule.Files.Path, indexPath: rule.Files.Index, responseHeaders: rule.Files.ResponseHeaders}
		r.Handler(spa)
	}
	if rule.Proxy != nil {
		u, err := url.Parse(rule.Proxy.Target)
		if err != nil {
			return fmt.Errorf("invalid target url: %w", err)
		}
		prox := httputil.NewSingleHostReverseProxy(u)
		if rule.OIDC {
			r.Handler(alb.OidcHandler(prox.ServeHTTP))
		} else {
			r.Handler(prox)
		}
	}
	return nil
}
