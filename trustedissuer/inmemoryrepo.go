package trustedissuer

import (
	"net/http"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

/**
* Quick in-memory implementation of the issuer repository. Should only be used for dev and testing, does not have any persistence.
 */
type InMemoryRepo struct{}

var issuerMap *map[string]model.TrustedIssuer = &map[string]model.TrustedIssuer{}

func (InMemoryRepo) CreateIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {
	if (*issuerMap)[trustedIssuer.Id] != (model.TrustedIssuer{}) {
		logger.Warnf("Issuer %s already exists.", logging.PrettyPrintObject(trustedIssuer))
		return model.HttpError{http.StatusConflict, "Issuer already exists.", nil}
	}
	(*issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (InMemoryRepo) GetIssuer(id string) (trustedIssuer model.TrustedIssuer, httpErr model.HttpError) {
	if (*issuerMap)[id] == (model.TrustedIssuer{}) {
		logger.Warnf("No such issuer %s exists.", id)
		return trustedIssuer, model.HttpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	return (*issuerMap)[id], httpErr
}

func (InMemoryRepo) DeleteIssuer(id string) (httpErr model.HttpError) {
	if (*issuerMap)[id] == (model.TrustedIssuer{}) {
		logger.Warnf("No such issuer %s exists.", id)
		return model.HttpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	delete(*issuerMap, id)
	return httpErr
}

func (InMemoryRepo) PutIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {
	if (*issuerMap)[trustedIssuer.Id] == (model.TrustedIssuer{}) {
		logger.Warnf("Issuer %s not found.", trustedIssuer.Id)
		return model.HttpError{http.StatusNotFound, "Issuer not found.", nil}
	}
	(*issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (InMemoryRepo) GetIssuers(limit int, offset int) (trustedIssuers []model.TrustedIssuer, httpErr model.HttpError) {
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
