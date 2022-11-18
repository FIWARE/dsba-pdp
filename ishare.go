package main

import "github.com/golang-jwt/jwt/v4"

/**
* Constant indicating the "permit" effect as defined by iShare
 */
const iSharePermitEffect string = "Permit"

// data structures defined by the [iShare-Delegation endpoint specification]: https://dev.ishareworks.org/delegation/endpoint.html

type PolicySet struct {
	MaxDelegationDepth int              `json:"maxDelegationDepth,omitempty"`
	Target             *PolicySetTarget `json:"target,omitempty"`
	Policies           []Policy         `json:"policies,omitempty"`
}

type Policy struct {
	Target *PolicyTarget `json:"target,omitempty"`
	Rules  []Rule        `json:"rules,omitempty"`
}

type Environment struct {
	ServiceProviders []string `json:"serviceProviders,omitempty"`
}

type Resource struct {
	Type        string   `json:"type,omitempty"`
	Identifiers []string `json:"identifiers,omitempty"`
	Attributes  []string `json:"attributes,omitempty"`
}

type PolicyTarget struct {
	Resource    *Resource    `json:"resource,omitempty"`
	Actions     []string     `json:"actions,omitempty"`
	Environment *Environment `json:"environment,omitempty"`
}

type Rule struct {
	Effect string      `json:"effect,omitempty"`
	Target *RuleTarget `json:"target,omitempty"`
}

type RuleTarget struct {
	Resource *Resource `json:"resource,omitempty"`
	Actions  []string  `json:"actions,omitempty"`
}

type PolicySetTarget struct {
	Environment *PolicySetEnvironment `json:"environment,omitempty"`
}

type PolicySetEnvironment struct {
	Licenses []string `json:"licenses,omitempty"`
}

type DelegationRequestWrapper struct {
	DelegationRequest *DelegationRequest `json:"delegationRequest,omitempty"`
}

type DelegationRequest struct {
	PolicyIssuer   string            `json:"policyIssuer,omitempty"`
	Target         *DelegationTarget `json:"target,omitempty"`
	PolicySets     []*PolicySet      `json:"policySets,omitempty"`
	DelegationPath []string          `json:"delegation_path,omitempty"`
	PreviousSteps  []string          `json:"previous_steps,omitempty"`
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

type IShareCredentialsSubject struct {
	// information about the authorization registry, to retrieve the policies for the issuer
	AuthorizationRegistry *AuthorizationRegistry `json:"authorizationRegistry"`
	Name                  string                 `json:"name,omitempty"`
	GivenName             string                 `json:"given_name,omitempty"`
	FamilyName            string                 `json:"family_name,omitempty"`
	PreferredUsername     string                 `json:"preferred_username,omitempty"`
	Email                 string                 `json:"email,omitempty"`
}

type AuthorizationRegistry struct {
	Id   string `json:"id"`
	Host string `json:"host"`
	// will use default path it not included - {host}/connect/token
	TokenPath string `json:"tokenPath,omitempty"`
	// will use default path it not included - {host}/delegation
	DelegationPath string `json:"delegationPath,omitempty"`
}

func (ar AuthorizationRegistry) getTokenAddress() string {
	if ar.TokenPath == "" {
		return ar.Host + "/connect/token"
	} else {
		return ar.Host + ar.TokenPath
	}
}

func (ar AuthorizationRegistry) getDelegationAddress() string {
	if ar.DelegationPath == "" {
		return ar.Host + "/delegation"
	} else {
		return ar.Host + ar.DelegationPath
	}
}
