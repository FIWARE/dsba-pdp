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
	*jwt.RegisteredClaims
}

type DSBAVerifiableCredential struct {
	Context           []string          `json:"@context,omitempty"`
	Id                string            `json:"id,omitempty"`
	Type              []string          `json:"type,omitempty"`
	Issuer            string            `json:"issuer,omitempty"`
	IssuanceDate      string            `json:"issuanceDate,omitempty"`
	ValidFrom         string            `json:"validFrom,omitempty"`
	ExpirationDate    string            `json:"expirationDate,omitempty"`
	CredentialSubject CredentialSubject `json:"credentialSubject,omitempty"`
}

type Role struct {
	// name of the role, for example READER
	Names    []string `json:"names,omitempty"`
	Target   string   `json:"target,omitempty"`
	Provider string   `json:"provider,omitempty"`
}

type CredentialSubject struct {
	Id    string `json:"id,omitempty"`
	Roles []Role `json:"roles,omitempty"`
	*IShareCredentialsSubject
}
