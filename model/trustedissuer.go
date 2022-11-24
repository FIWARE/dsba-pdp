package model

type TrustedIssuer struct {
	Id           string        `json:"id"`
	Capabilities *[]Capability `json:"capabilities"`
}

type Capability struct {
	ValidFor        *TimeRange   `json:"validFor,omitempty"`
	CredentialsType string       `json:"credentialsType,omitempty"`
	Claims          *[]Claim     `json:"claims,omitempty"`
	Policy          *interface{} `json:"policy,omitempty"`
}

type TimeRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type Claim struct {
	Name          string   `json:"name"`
	AllowedValues []string `json:"AllowedValues"`
}

type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}
