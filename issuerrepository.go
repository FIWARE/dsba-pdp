package main

type IssuerRepository interface {
	CreateIssuer(trustedIssuer TrustedIssuer) httpError
	GetIssuer(id string) (trustedIssuer TrustedIssuer, httpErr httpError)
	DeleteIssuer(id string) httpError
	PutIssuer(trustedIssuer TrustedIssuer) httpError
	GetIssuers(limit int, offset int) (trustedIssuers []TrustedIssuer, httpErr httpError)
}
