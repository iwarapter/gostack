package apigw

import (
	"fmt"
	"net/http"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/mitchellh/mapstructure"
)

type XAmazonAPIGatewayAuthorizer struct {
	Type                         string `json:"type,omitempty" yaml:"type,omitempty"`
	AuthorizerURI                string `json:"authorizerUri,omitempty" yaml:"authorizerUri,omitempty"`
	IdentitySource               string `json:"identitySource,omitempty" yaml:"identitySource,omitempty"`
	AuthorizerResultTTLInSeconds int    `json:"authorizerResultTtlInSeconds,omitempty" yaml:"authorizerResultTtlInSeconds,omitempty"`
}

type XAmazonApigatewayIntegration struct {
	Type                string `json:"type" yaml:"type"`
	URI                 string `json:"uri" yaml:"uri"`
	HTTPMethod          string `json:"httpMethod" yaml:"httpMethod"`
	PassthroughBehavior string `json:"passthroughBehavior" yaml:"passthroughBehavior"`
}

func (api *API) Import(spec *openapi3.T) error {
	for path, item := range spec.Paths {
		if item.Get != nil {
			if err := api.addOperationToAPI(spec, item.Get, http.MethodGet, path); err != nil {
				return err
			}
		}
		if item.Post != nil {
			if err := api.addOperationToAPI(spec, item.Post, http.MethodPost, path); err != nil {
				return err
			}
		}
		if item.Delete != nil {
			if err := api.addOperationToAPI(spec, item.Delete, http.MethodDelete, path); err != nil {
				return err
			}
		}
		if item.Put != nil {
			if err := api.addOperationToAPI(spec, item.Put, http.MethodPut, path); err != nil {
				return err
			}
		}
	}

	return nil
}

func (api *API) addOperationToAPI(spec *openapi3.T, op *openapi3.Operation, method, path string) error {
	if ext, ok := op.Extensions["x-amazon-apigateway-integration"]; ok {
		var data XAmazonApigatewayIntegration
		if err := mapstructure.Decode(ext, &data); err != nil {
			return fmt.Errorf("unable to parse x-amazon-apigateway-integration extension for %s error: %w", path, err)
		} else {
			secReqs := make([]openapi3.SecurityRequirement, 0)
			secReqs = append(secReqs, spec.Security...)
			if op.Security != nil && len(*op.Security) > 0 {
				secReqs = append(secReqs, *op.Security...)
			}
			if len(secReqs) > 0 {
				// we are going to assume one for now
				auths := make([]string, 0)
				for _, req := range secReqs {
					for k := range req {
						auths = append(auths, k)
					}
				}
				for _, name := range auths {
					if sec, ok := spec.Components.SecuritySchemes[name]; ok {
						if val, ok := sec.Value.Extensions["x-amazon-apigateway-authorizer"]; ok {
							var auth XAmazonAPIGatewayAuthorizer
							if err := mapstructure.Decode(val, &auth); err != nil {
								return fmt.Errorf("unable to parse x-amazon-apigateway-authorizer extension for %s error: %w", name, err)
							}
							handler := Logger(api.Authorizer(auth.AuthorizerURI, auth.Type, api.LambdaProxy(data.URI)), op.OperationID)
							api.router.Methods(method).Path(path).Name(op.OperationID).Handler(handler)
						} else {
							// if _, ok := sec.Value.Extensions["sigv4"]; ok {
							// TODO something sig4
							handler := Logger(api.LambdaProxy(data.URI), op.OperationID)
							api.router.Methods(method).Path(path).Name(op.OperationID).Handler(handler)
						}
					} else {
						return fmt.Errorf("something didnt work 2")
					}
				}
			} else {
				handler := Logger(api.LambdaProxy(data.URI), op.OperationID)
				api.router.Methods(method).Path(path).Name(op.OperationID).Handler(handler)
			}
		}
	}
	return nil
}
