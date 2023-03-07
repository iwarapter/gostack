# GoStack

Quick and dirty testing util to spin up lambda processes and invoke them as API GW targets (with authorizers) and also an ALB.


See below for quick example:

`gostack.yml`
```yaml
lambdas:
  - name: example
    zip: example.zip
    timeout: 5
    environment:
      FOO: BAR
apigateways:
  - id: example
    openapi-spec: swagger.json
albs:
  - rules:
    - path: /config
      oidc: true
      methods:
        - GET
      fixed-response:
        body: '{"foo":"bar"}'
        content-type: application/json
    - path: /foo
      methods:
        - POST
      oidc: true
      target: arn:aws:lambda:us-east-1:123456789012:function:one
    - path: /
      oidc: true
      files:
        path: dist/
        index: index.html
```
Lambdas should be compiled for `local` OS/ARCH (i.e: `go build -o bootstrap`).

API Gateways will import from OpenAPI spec, AWS tags for authorizer/lambda integration are honoured.

ALB - Configuration rules, `fixed-response`, `target` or files (served like an SPA).

ALB - Auth, the ALB has a very hacky thrown together oauth flow, the login page simply takes all the relevant information
and then presents it. For easy testing of different user/configuration scenarios.
