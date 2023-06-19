# GoStack

Quick and dirty testing util to spin up lambda processes and invoke them as API GW targets (with authorizers) and also an ALB.

## Usage

```bash
$ gostack --help
Usage:
  main [OPTIONS]

Application Options:
  -c, --config= Path to the configuration file (default: gostack.yml)
  -p, --port=   Listener port (default: 8080)

Help Options:
  -h, --help    Show this help message
```

See below for quick example:

`gostack.yml`
```yaml
lambdas:
  - name: example
    zip: example.zip
    timeout: 5
    environment:
      FOO: BAR
      API_KEY: ${API_KEY}
apigateways:
  - id: example
    openapi-spec: swagger.json
albs:
  - id: default
    default-introspection: '{"active": true,"scope": "openid email"}'
    default-userinfo: '{"foo":"bar"}'
    rules:
    - path: /config
      oidc: true
      methods:
        - GET
      fixed-response:
        body: '{"foo":"bar"}'
        content-type: application/json
    - path: /foo
      headers:
        accept: application/json
      methods:
        - POST
      oidc: true
      target: arn:aws:lambda:us-east-1:123456789012:function:one
    - path: /
      oidc: true
      files:
        path: dist/
        index: index.html

mock-data:
  "my-example-token":
    userinfo:
      scope: foo
      other: bar
    introspection:
      active: true
      scope: "openid email example"
```

## Lambdas

Lambdas should be compiled for `local` OS/ARCH (i.e: `go build -o bootstrap`).

Environment variables are passed to the lambda configuration as `FOO=BAR` and the `bootstrap` process is invoked with the `FOO=BAR` environment variables.

Variables defined with `${}` will be replaced with the value of the environment variable.
Example:
```yaml
environment:
  FOO: BAR
  API_KEY: ${API_KEY}
```

## API Gateways

API Gateways will import from OpenAPI spec, AWS tags for authorizer/lambda integration are honoured.

### Lambda Integrations

Lambda integrations are defined in the OpenAPI spec, the `x-amazon-apigateway-integration` tag is used to define the lambda integration.

Example:
```yaml
paths:
  /foo:
    get:
      x-amazon-apigateway-integration:
        uri: arn:aws:lambda:us-east-1:123456789012:function:one
        passthroughBehavior: when_no_match
        httpMethod: POST
        type: aws_proxy
```

### Authorizers

Authorizers are defined in the OpenAPI spec, the `x-amazon-apigateway-authtype` tag is used to define the type of authorizer.

Example:
```yaml
paths:
  /foo:
    get:
      security:
        - authorizer: []
      x-amazon-apigateway-integration:
        uri: arn:aws:lambda:us-east-1:123456789012:function:one
        passthroughBehavior: when_no_match
        httpMethod: POST
        type: aws_proxy
components:
  securitySchemes:
    authorizer:
      type: apiKey
      name: Authorization
      in: header
      x-amazon-apigateway-authtype: custom
      x-amazon-apigateway-authorizer:
        authorizerUri: arn:aws:lambda:us-east-1:123456789012:function:auth
        authorizerResultTtlInSeconds: 300
        type: request
        identitySource : method.request.header.Authorization
```

Both `request` and `token` authorizers are supported.

## Application Load Balancers

ALB - Configuration rules, `fixed-response`, `target` or files (served like an SPA).

### Fixed Response

The `fixed-response` rule will return a fixed response with the provided body and content-type.

Example:
```yaml
albs:
  - rules:
    - path: /config
      oidc: true
      methods:
        - GET
      fixed-response:
        body: '{"foo":"bar"}'
        content-type: application/json
```

### Target

The `target` rule will invoke the lambda function with the provided ARN.

Example:
```yaml
albs:
  - rules:
    - path: /foo
      methods:
        - POST
      oidc: true
      target: arn:aws:lambda:us-east-1:123456789012:function:one
```

### Files

The `files` rule will serve files from the provided path, the `index` file will be served for the root path.

Example:
```yaml
albs:
  - rules:
    - path: /
      oidc: true
      files:
        path: dist/
        index: index.html
```

### Headers

The `headers` rule will match on the provided headers. Headers are key/value pairs.

Example:
```yaml
albs:
  - rules:
    - path: /foo
      headers:
        accept: application/json
      methods:
        - POST
      oidc: true
      target: arn:aws:lambda:us-east-1:123456789012:function:one
```

### OIDC

The `oidc` rule will require the user to be authenticated via OIDC.

### ALB Auth

ALB - Auth, the ALB has a very hacky thrown together oauth flow, the login page simply takes all the relevant information
and then presents it. For easy testing of different user/configuration scenarios.

The auth domain is `auth.127.0.0.1.nip.io:8080` and the login page is `auth.127.0.0.1.nip.io:8080/login`.

The auth also signs the JWT with a static key, so the JWT can be decoded to see the contents. The JWT is signed according to the AWS ALB spec, which is non-standard (yay).

It supports settings the OIDC subject, the introspection response and the userinfo response. The cookie lifetime is also configurable.

## Mock-Data

The mock-data section is used to provide mock data for the OIDC flow. The key is the token that will be used to identify the user.

The `userinfo` section is used to provide the user information that will be returned by the userinfo endpoint.

The `introspection` section is used to provide the introspection information that will be returned by the introspection endpoint.

All claims for the `userinfo` and `introspection` sections are optional. If a claim is not provided, it will not be returned. All data is marshalled to JSON, so the values should be valid JSON values.
