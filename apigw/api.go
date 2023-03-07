package apigw

import (
	"context"
	"fmt"

	cache "github.com/Code-Hex/go-generics-cache"
	"github.com/aws/aws-lambda-go/events"
	"github.com/gorilla/mux"
	"github.com/iwarapter/gostack/lambstack"
	"github.com/rs/zerolog/log"
)

type API struct {
	ID        string
	router    *mux.Router
	lambs     lambstack.LambdaFactory
	authCache *cache.Cache[string, events.APIGatewayCustomAuthorizerResponse]
}

// const alphaNumeric = "1234567890abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
//
// func generateApiGatewayID(n int) string {
//	b := make([]byte, n)
//	for i := range b {
//		b[i] = alphaNumeric[rand.Intn(len(alphaNumeric))]
//	}
//	return string(b)
//}

func New(subrouter *mux.Router, lambs lambstack.LambdaFactory, id string) *API {
	log.Info().Str("apid_id", id).Msg("creating api gateway")
	router := subrouter.PathPrefix(fmt.Sprintf("/%s", id)).Subrouter()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	api := &API{
		ID:        id,
		router:    router,
		authCache: cache.NewContext[string, events.APIGatewayCustomAuthorizerResponse](ctx),
		lambs:     lambs,
	}

	return api
}
