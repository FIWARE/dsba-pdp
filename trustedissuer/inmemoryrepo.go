package trustedissuer

import (
	"net/http"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
)

/**
* Quick in-memory implementation of the issuer repository. Should only be used for dev and testing, does not have any persistence.
 */
type InMemoryRepo struct {
	issuerMap *map[string]model.TrustedIssuer
}

func NewInmemoryRepo() *InMemoryRepo {
	inmemoryRepo := new(InMemoryRepo)
	inmemoryRepo.issuerMap = &map[string]model.TrustedIssuer{}
	return inmemoryRepo

}

func (inMemoryRepo InMemoryRepo) CreateIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {
	if trustedIssuer.Id == "" {
		logger.Infof("Failed to create issuer %s because of missing id.", logging.PrettyPrintObject(trustedIssuer))
		return model.HttpError{Status: http.StatusBadRequest, Message: "Issuer id is required.", RootError: nil}
	}
	if (*inMemoryRepo.issuerMap)[trustedIssuer.Id] != (model.TrustedIssuer{}) {
		logger.Warnf("Issuer %s already exists.", logging.PrettyPrintObject(trustedIssuer))
		return model.HttpError{Status: http.StatusConflict, Message: "Issuer already exists.", RootError: nil}
	}
	(*inMemoryRepo.issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (inMemoryRepo InMemoryRepo) GetIssuer(id string) (trustedIssuer model.TrustedIssuer, httpErr model.HttpError) {
	if (*inMemoryRepo.issuerMap)[id] == (model.TrustedIssuer{}) {
		logger.Warnf("No such issuer %s exists.", id)
		return trustedIssuer, model.HttpError{Status: http.StatusNotFound, Message: "Issuer not found.", RootError: nil}
	}
	return (*inMemoryRepo.issuerMap)[id], httpErr
}

func (inMemoryRepo InMemoryRepo) DeleteIssuer(id string) (httpErr model.HttpError) {
	_, ok := (*inMemoryRepo.issuerMap)[id]
	if !ok {
		logger.Warnf("No such issuer %s exists.", id)
		return model.HttpError{Status: http.StatusNotFound, Message: "Issuer not found.", RootError: nil}
	}
	delete(*inMemoryRepo.issuerMap, id)
	return httpErr
}

func (inMemoryRepo InMemoryRepo) PutIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {
	if (*inMemoryRepo.issuerMap)[trustedIssuer.Id] == (model.TrustedIssuer{}) {
		logger.Warnf("Issuer %s not found.", trustedIssuer.Id)
		return model.HttpError{Status: http.StatusNotFound, Message: "Issuer not found.", RootError: nil}
	}
	(*inMemoryRepo.issuerMap)[trustedIssuer.Id] = trustedIssuer
	return httpErr
}

func (inMemoryRepo InMemoryRepo) GetIssuers(limit int, offset int) (trustedIssuers []model.TrustedIssuer, httpErr model.HttpError) {
	counter := 0
	for _, issuer := range *inMemoryRepo.issuerMap {
		if counter >= offset {
			trustedIssuers = append(trustedIssuers, issuer)
		}
		if len(trustedIssuers) == limit {
			return trustedIssuers, httpErr
		}
	}
	return trustedIssuers, httpErr
}
