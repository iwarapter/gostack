package main

import (
	"net/http"
	"os"
	"time"

	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/service/lambda"
	"github.com/getkin/kin-openapi/openapi3"
	"github.com/gorilla/handlers"
	"github.com/gorilla/mux"
	"github.com/iwarapter/gostack/alb"
	"github.com/iwarapter/gostack/apigw"
	"github.com/iwarapter/gostack/config"
	"github.com/iwarapter/gostack/lambstack"
	"github.com/rs/cors"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"gopkg.in/yaml.v3"
)

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
			Str("host", r.Host).
			Str("request_uri", r.URL.Path).
			Dur("duration", time.Since(start)).
			Int("status_code", dw.StatusCode()).
			Send()
	})
}

func main() {
	log.Logger = log.Output(zerolog.ConsoleWriter{Out: os.Stderr})

	b, err := os.ReadFile("gostack.yml")
	if err != nil {
		log.Fatal().Err(err).Msg("unable to load gostack file")
	}
	var stack config.GoStack
	err = yaml.Unmarshal(b, &stack)
	if err != nil {
		log.Fatal().Err(err).Msg("unable to load gostack file")
	}

	lambs := lambstack.New()
	defer lambs.Close()
	router, err := setupStack(stack, lambs)
	if err != nil {
		log.Error().Err(err).Msg("unable to setup stack")
		return
	}
	srv := &http.Server{
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		Handler:      router,
		Addr:         ":8080",
	}
	log.Error().Err(srv.ListenAndServe()).Send()
}

func setupStack(stack config.GoStack, lambs lambstack.LambdaFactory) (http.Handler, error) {
	router := mux.NewRouter()
	router.Use(Logger)

	apiRouter := router.Host("api.127.0.0.1.nip.io").Subrouter()
	apiRouter = apiRouter.PathPrefix("/restapis").Subrouter()
	headersOk := handlers.AllowedHeaders([]string{"Content-Type"})
	originsOk := handlers.AllowedOrigins([]string{"https://alb.127.0.0.1.nip.io:8080"})
	methodsOk := handlers.AllowedMethods([]string{"GET", "HEAD", "POST", "PUT", "OPTIONS"})
	apiRouter.Use(handlers.CORS(originsOk, headersOk, methodsOk, handlers.AllowCredentials()))

	for _, l := range stack.Lambdas {
		log.Info().Str("lambda", l.Name).Str("path", l.Zip).Msg("adding lambda")
		contents, err := os.ReadFile(l.Zip)
		if err != nil {
			log.Error().Err(err).Str("lambda", l.Name).Str("path", l.Zip).Msg("unable to load lambda zip")
			return nil, err
		}
		arn, err := lambs.Add(lambda.CreateFunctionInput{
			Timeout:      aws.Int64(5),
			FunctionName: aws.String(l.Name),
			Code: &lambda.FunctionCode{
				ZipFile: contents,
			},
			Environment: &lambda.Environment{
				Variables: l.Environment,
			},
		})
		if err != nil {
			log.Error().Err(err).Str("lambda", l.Name).Msg("unable to create lambda")
			return nil, err
		}
		log.Info().Str("arn", arn).Msg("lambda started successfully")
	}

	for _, apicfg := range stack.APIs {
		api := apigw.New(apiRouter, lambs, apicfg.ID)
		loader := openapi3.NewLoader()
		doc, err := loader.LoadFromFile(apicfg.OA3path)
		if err != nil {
			log.Error().Err(err).Str("apigw", apicfg.ID).Str("path", apicfg.OA3path).Msg("unable to load openapi3 spec from file")
			return nil, err
		}
		err = api.Import(doc)
		if err != nil {
			log.Error().Err(err).Str("apigw", apicfg.ID).Str("path", apicfg.OA3path).Msg("unable to import openapi3 spec into router")
			return nil, err
		}
	}

	lb := alb.New(router, lambs, stack.MockData)
	for _, a := range stack.ALBs {
		for _, rule := range a.Rules {
			err := lb.AddRule(rule)
			if err != nil {
				log.Error().Err(err).Str("rule", rule.Path).Msg("unable to load alb rule")
				return nil, err
			}
		}
	}
	if err := router.Walk(func(route *mux.Route, router *mux.Router, ancestors []*mux.Route) error {
		methods, _ := route.GetMethods()
		host, _ := route.GetHostTemplate()
		path, _ := route.GetPathTemplate()
		log.Info().Str("host", host).Strs("methods", methods).Str("path", path).Send()
		return nil
	}); err != nil {
		log.Error().Err(err).Msg("unable to walk the router")
		return nil, err
	}

	crs := cors.New(cors.Options{
		AllowCredentials: true,
		AllowedMethods:   []string{"GET", "HEAD", "POST", "PUT", "OPTIONS"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowedOrigins:   []string{""},
		AllowOriginFunc:  func(origin string) bool { return true },
	})
	return crs.Handler(router), nil
}
