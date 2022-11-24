package trustedissuer

import (
	"os"

	"github.com/wistefan/dsba-pdp/model"
)

/**
* Repository used to store trusted issuers
 */
var issuerRepo IssuerRepository

type IssuerRepository interface {
	CreateIssuer(trustedIssuer model.TrustedIssuer) model.HttpError
	GetIssuer(id string) (trustedIssuer model.TrustedIssuer, httpErr model.HttpError)
	DeleteIssuer(id string) model.HttpError
	PutIssuer(trustedIssuer model.TrustedIssuer) model.HttpError
	GetIssuers(limit int, offset int) (trustedIssuers []model.TrustedIssuer, httpErr model.HttpError)
}

func init() {
	mySql := os.Getenv("MYSQL_HOST")

	if mySql != "" {
		issuerRepo = MySqlRepo{}
		logger.Infof("Connected to mysql as storage backend.")
	} else {
		logger.Warn("Issuer repository is kept in-memory. No persistence will be applied, do NEVER use this for anything but development or testing!")
		issuerRepo = InMemoryRepo{}
	}
}
func IssuerRepo() IssuerRepository {
	return issuerRepo
}
