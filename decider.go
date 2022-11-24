package main

import "github.com/golang-jwt/jwt/v4"

// interface of the configured decider

type Decider interface {
	Decide(token *DSBAToken, originalAddress string, requestType string, requestBody *map[string]interface{}) (descision Decision, err httpError)
}

// error interface

type Decision struct {
	Decision bool   `json:"decision"`
	Reason   string `json:"reason"`
}

type httpError struct {
	status    int
	message   string
	rootError error
}

func (err *httpError) Error() string {
	return err.message
}

func (err *httpError) GetRoot() error {
	return err.rootError
}

// token as used by the dsba-mvf

type DSBAToken struct {
	VerifiableCredential DSBAVerifiableCredential `json:"verifiableCredential"`
	jwt.RegisteredClaims
}

type DSBAVerifiableCredential struct {
	Context           []string          `json:"@context"`
	Id                string            `json:"id"`
	Type              []string          `json:"type"`
	Issuer            string            `json:"issuer"`
	IssuanceDate      string            `json:"issuanceDate"`
	ValidFrom         string            `json:"validFrom"`
	ExpirationDate    string            `json:"expirationDate"`
	CredentialSubject CredentialSubject `json:"credentialSubject"`
}

type Role struct {
	// name of the role, for example READER
	Name     []string `json:"name"`
	Target   string   `json:"target"`
	Provider string   `json:"provider,omitempty"`
}

type CredentialSubject struct {
	Id    string `json:"id"`
	Roles []Role `json:"roles"`
	*IShareCredentialsSubject
}
