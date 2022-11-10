package main

import (
	"net/http"
)

var issuerMap *map[string]TrustedIssuer = &map[string]TrustedIssuer{}

func (InMemoryRepo) CreateIssuer(trustedIssuer TrustedIssuer) (httpErr httpError) {
	if (*issuerMap)[trustedIssuer.Id] != (TrustedIssuer{}) {
		logger.Warnf("Issuer %s already exists.", prettyPrintObject(trustedIssuer))
		return httpError{http.StatusConflict, "Issuer already exists.", nil}
	}
	(*issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (InMemoryRepo) GetIssuer(id string) (trustedIssuer TrustedIssuer, httpErr httpError) {
	if (*issuerMap)[id] == (TrustedIssuer{}) {
		logger.Warnf("No such issuer %s exists.", id)
		return trustedIssuer, httpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	return (*issuerMap)[id], httpErr
}

func (InMemoryRepo) DeleteIssuer(id string) (httpErr httpError) {
	if (*issuerMap)[id] == (TrustedIssuer{}) {
		logger.Warnf("No such issuer %s exists.", id)
		return httpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	delete(*issuerMap, id)
	return httpErr
}

func (InMemoryRepo) PutIssuer(trustedIssuer TrustedIssuer) (httpErr httpError) {
	if (*issuerMap)[trustedIssuer.Id] == (TrustedIssuer{}) {
		logger.Warnf("Issuer %s not found.", trustedIssuer.Id)
		return httpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	(*issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (InMemoryRepo) GetIssuers(limit int, offset int) (trustedIssuers []TrustedIssuer, httpErr httpError) {
	counter := 0
	for _, issuer := range *issuerMap {
		if counter >= offset {
			trustedIssuers = append(trustedIssuers, issuer)
		}
		if len(trustedIssuers) == limit {
			return trustedIssuers, httpErr
		}
	}
	return trustedIssuers, httpErr
}

type InMemoryRepo struct{}
