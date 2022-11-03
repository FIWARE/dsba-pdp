package main

import "github.com/golang-jwt/jwt/v4"

type PolicySet struct {
	MaxDelegationDepth int             `json:"maxDelegationDepth"`
	Target             PolicySetTarget `json:"target"`
	Policies           []Policy        `json:"policies"`
}

type Policy struct {
	Target PolicyTarget `json:"target"`
	Rules  []Rule       `json:"rules"`
}

type Environment struct {
	ServiceProviders []string `json:"serviceProviders"`
}

type Resource struct {
	Type        string   `json:"type"`
	Identifiers []string `json:"identifiers"`
	Attributes  []string `json:"attributes"`
}

type PolicyTarget struct {
	Resource    Resource    `json:"resource"`
	Actions     []string    `json:"actions"`
	Environment Environment `json:"environment"`
}

type Rule struct {
	Effect string     `json:"effect"`
	Target RuleTarget `json:"target"`
}

type RuleTarget struct {
	Resource Resource `json:"resource"`
	Actions  []string `json:"actions"`
}

type PolicySetTarget struct {
	Environment PolicySetEnvironment `json:"environment"`
}

type PolicySetEnvironment struct {
	Licenses []string `json:"licenses"`
}

type DelegationRequest struct {
	PolicyIssuer   string           `json:"policyIssuer"`
	Target         DelegationTarget `json:"target"`
	PolicySets     []PolicySet      `json:"policySets"`
	DelegationPath []string         `json:"delegation_path"`
	PreviousSteps  []string         `json:"previous_steps"`
}

type DelegationTarget struct {
	AccessSubject string `json:"accessSubject"`
}

type DelegationResponse struct {
	DelegationToken string `json:"delegation_token"`
}

type Delegation struct {
	Issuer             string             `json:"iss"`
	Subject            string             `json:"sub"`
	JwtId              string             `json:"jti"`
	IssuedAt           int                `json:"iat"`
	Expiry             int                `json:"exp"`
	Audience           string             `json:"aud"`
	DelegationEvidence DelegationEvidence `json:"delegationEvidence"`
}

type DelegationEvidence struct {
	NotBefore    int64            `json:"notBefore"`
	NotOnOrAfter int64            `json:"notOnOrAfter"`
	PolicyIssuer string           `json:"policyIssuer"`
	Target       DelegationTarget `json:"target"`
	PolicySets   []PolicySet      `json:"policySets"`
}

type IShareToken struct {
	DelegationEvidence DelegationEvidence `json:"delegationEvidence"`
	jwt.RegisteredClaims
}
