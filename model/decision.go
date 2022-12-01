package model

import "github.com/golang-jwt/jwt/v4"

// error interface

type Decision struct {
	Decision bool   `json:"decision"`
	Reason   string `json:"reason"`
}

type HttpError struct {
	Status    int
	Message   string
	RootError error
}

func (err *HttpError) Error() string {
	return err.Message
}

func (err *HttpError) GetRoot() error {
	return err.RootError
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
