package main

import "github.com/golang-jwt/jwt/v4"

type PolicySet struct {
	MaxDelegationDepth int             `json:"maxDelegationDepth,omitempty"`
	Target             PolicySetTarget `json:"target,omitempty"`
	Policies           []Policy        `json:"policies,omitempty"`
}

type Policy struct {
	Target PolicyTarget `json:"target,omitempty"`
	Rules  []Rule       `json:"rules,omitempty"`
}

type Environment struct {
	ServiceProviders []string `json:"serviceProviders"`
}

type Resource struct {
	Type        string   `json:"type,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
	Attributes  []string `json:"attributes,omitempty"`
}

type PolicyTarget struct {
	Resource    Resource    `json:"resource,omitempty"`
	Actions     []string    `json:"actions,omitempty"`
	Environment Environment `json:"environment,omitempty"`
}

type Rule struct {
	Effect string     `json:"effect,omitempty"`
	Target RuleTarget `json:"target,omitempty"`
}

type RuleTarget struct {
	Resource Resource `json:"resource,omitempty"`
	Actions  []string `json:"actions,omitempty"`
}

type PolicySetTarget struct {
	Environment PolicySetEnvironment `json:"environment,omitempty"`
}

type PolicySetEnvironment struct {
	Licenses []string `json:"licenses,omitempty"`
}

type DelegationRequestWrapper struct {
	DelegationRequest DelegationRequest `json:"delegationRequest,omitempty"`
}

type DelegationRequest struct {
	PolicyIssuer   string           `json:"policyIssuer,omitempty"`
	Target         DelegationTarget `json:"target,omitempty"`
	PolicySets     []PolicySet      `json:"policySets,omitempty"`
	DelegationPath []string         `json:"delegation_path,omitempty"`
	PreviousSteps  []string         `json:"previous_steps,omitempty"`
}

type DelegationTarget struct {
	AccessSubject string `json:"accessSubject,omitempty"`
}

type DelegationResponse struct {
	DelegationToken string `json:"delegation_token,omitempty"`
}

type Delegation struct {
	Issuer             string             `json:"iss,omitempty"`
	Subject            string             `json:"sub,omitempty"`
	JwtId              string             `json:"jti,omitempty"`
	IssuedAt           int                `json:"iat,omitempty"`
	Expiry             int                `json:"exp,omitempty"`
	Audience           string             `json:"aud,omitempty"`
	DelegationEvidence DelegationEvidence `json:"delegationEvidence,omitempty"`
}

type DelegationEvidence struct {
	NotBefore    int64            `json:"notBefore,omitempty"`
	NotOnOrAfter int64            `json:"notOnOrAfter,omitempty"`
	PolicyIssuer string           `json:"policyIssuer,omitempty"`
	Target       DelegationTarget `json:"target,omitempty"`
	PolicySets   []PolicySet      `json:"policySets,omitempty"`
}

type IShareToken struct {
	DelegationEvidence DelegationEvidence `json:"delegationEvidence,omitempty"`
	jwt.RegisteredClaims
}
