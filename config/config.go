package config

type GoStack struct {
	APIs     []APIGW             `yaml:"apigateways"`
	ALBs     []ALB               `yaml:"albs"`
	Lambdas  []Lambda            `yaml:"lambdas"`
	MockData map[string]MockData `yaml:"mock-data"`
}

type MockData struct {
	Introspection map[string]any `yaml:"introspection"`
	Userinfo      map[string]any `yaml:"userinfo"`
}

type APIGW struct {
	ID      string `yaml:"id"`
	OA3path string `yaml:"openapi-spec"`
}

type ALB struct {
	Rules []ALBRule `yaml:"rules"`
}

type ALBRule struct {
	Path          string            `yaml:"path"`
	Methods       []string          `yaml:"methods"`
	Headers       map[string]string `yaml:"headers"`
	FixedResponse *FixedResponse    `yaml:"fixed-response,omitempty"`
	Target        string            `yaml:"target"`
	OIDC          bool              `yaml:"oidc"`
	Files         *FileServer       `yaml:"files"`
}

type FileServer struct {
	Path  string `yaml:"path"`
	Index string `yaml:"index"`
}

type FixedResponse struct {
	Body        string `yaml:"body"`
	ContentType string `yaml:"content-type"`
}

type Lambda struct {
	Name        string             `yaml:"name"`
	Zip         string             `yaml:"zip"`
	Timeout     int                `yaml:"timeout"`
	Environment map[string]*string `yaml:"environment"`
}
