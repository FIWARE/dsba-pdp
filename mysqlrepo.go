package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/go-rel/mysql"
	"github.com/go-rel/rel"
	"github.com/go-rel/rel/where"
	_ "github.com/go-sql-driver/mysql"
	dbModel "github.com/wistefan/dsba-pdp/sql"
)

type MySqlRepo struct{}

var repo rel.Repository

func init() {

	var err error

	mysqlHost := os.Getenv("MYSQL_HOST")
	if mysqlHost == "" {
		logger.Info("No mysql host configured, mysql repo not available.")
		return
	}
	var mySqlPort int
	mysqlPortEnv := os.Getenv("MYSQL_PORT")
	if mysqlPortEnv != "" {
		mySqlPort, err = strconv.Atoi(mysqlPortEnv)
		if err != nil {
			logger.Fatalf("Invalid mysql port configured: %s", mysqlPortEnv)
		}
	} else {
		mySqlPort = 3306
	}
	mysqlDb := os.Getenv("MYSQL_DATABASE")
	if mysqlDb == "" {
		logger.Info("No mysql db configured, mysql repo not available.")
		return
	}
	authEnabled := true

	mysqlUser := os.Getenv("MYSQL_USERNAME")
	mysqlPassword := os.Getenv("MYSQL_PASSWORD")

	if mysqlUser == "" {
		logger.Infof("No user configured for mySql, will try to connect as root.")
		mysqlUser = "root"
	}

	if mysqlPassword == "" {
		logger.Infof("No password configured for mySql, will try to connect without credentials.")
		authEnabled = false
	}

	var connectionString string
	if authEnabled {
		connectionString = fmt.Sprintf("%s:%s@tcp(%s:%d)/%s", mysqlUser, mysqlPassword, mysqlHost, mySqlPort, mysqlDb)
	} else {
		connectionString = fmt.Sprintf("%s@tcp(%s:%d)/%s", mysqlUser, mysqlHost, mySqlPort, mysqlDb)
	}

	adapter, err := mysql.Open(connectionString)
	if err != nil {
		logger.Fatalf("Was not able to connect to db: %s:%d/%s as user %s.", mysqlHost, mySqlPort, mysqlDb, mysqlUser, err)
		return
	}
	repo = rel.New(adapter)

}

func (MySqlRepo) CreateIssuer(trustedIssuer TrustedIssuer) (httpErr httpError) {
	err := repo.Find(context.TODO(), &dbModel.TrustedIssuer{}, where.Eq("id", trustedIssuer.Id))
	if err == nil {
		return httpError{status: http.StatusConflict, message: "Issuer already exists.", rootError: nil}
	}
	logger.Infof("Error %v", err.Error())

	sqlIssuer := toSqlIssuer(trustedIssuer)
	logger.Infof("Issuer %s", prettyPrintObject(sqlIssuer))
	err = persistIssuer(sqlIssuer)
	if err != nil {
		return httpError{status: http.StatusInternalServerError, message: "Was not able to store issuer.", rootError: err}
	}

	return httpErr
}

func (MySqlRepo) GetIssuer(id string) (trustedIssuer TrustedIssuer, httpErr httpError) {

	sqlIssuer, httpErr := getSqlIssuer(id)
	if httpErr != (httpError{}) {
		return trustedIssuer, httpErr
	}
	return fromSqlIssuer(sqlIssuer), httpErr
}

func getSqlIssuer(id string) (trustedIssuer dbModel.TrustedIssuer, httpErr httpError) {
	ctx := context.TODO()

	var dbIssuer dbModel.TrustedIssuer = dbModel.TrustedIssuer{}

	err := repo.Find(ctx, &dbIssuer, where.Eq("id", id))
	if err != nil {
		return trustedIssuer, httpError{status: http.StatusNotFound, message: fmt.Sprintf("Issuer %s not found.", id), rootError: nil}
	}
	if err != nil {
		return trustedIssuer, httpError{status: http.StatusInternalServerError, message: "Was not able to load capabilities", rootError: err}
	}
	loadedCapabilities := []dbModel.Capability{}
	for _, capability := range dbIssuer.Capabilities {
		err = repo.Find(ctx, &capability, where.Eq("id", capability.ID))
		if err != nil {
			return trustedIssuer, httpError{status: http.StatusInternalServerError, message: "Was not able to load claims.", rootError: err}
		}
		loadedClaims := []dbModel.Claim{}
		for _, claim := range capability.Claims {
			err = repo.Find(ctx, &claim, where.Eq("id", claim.ID))
			if err != nil {
				return trustedIssuer, httpError{status: http.StatusInternalServerError, message: "Was not able to load allowed values.", rootError: err}
			}
			loadedClaims = append(loadedClaims, claim)
		}
		capability.Claims = loadedClaims
		loadedCapabilities = append(loadedCapabilities, capability)
	}
	dbIssuer.Capabilities = loadedCapabilities
	return dbIssuer, httpErr
}

func (MySqlRepo) DeleteIssuer(id string) (httpErr httpError) {
	return deleteIssuer(id)
}

func deleteIssuer(id string) (httpErr httpError) {
	sqlIssuer, httpErr := getSqlIssuer(id)
	if httpErr != (httpError{}) {
		return httpErr
	}

	ctx := context.TODO()

	err := repo.Transaction(ctx, func(ctx context.Context) error {
		for _, capability := range sqlIssuer.Capabilities {
			for _, claim := range capability.Claims {
				for _, allowedValue := range claim.AllowedValues {
					err := repo.Delete(ctx, &allowedValue)
					if err != nil {
						logger.Infof("Was not able to delete allowedValue %s", allowedValue.ID)
						return err
					}
				}
				err := repo.Delete(ctx, &claim)
				if err != nil {
					logger.Infof("Was not able to delete claim %s", claim.ID)
					return err
				}
			}
			err := repo.Delete(ctx, &capability)
			if err != nil {
				logger.Infof("Was not able to delete capability %s", capability.ID)
				return err
			}
		}
		return repo.Delete(ctx, &sqlIssuer)
	})

	if err != nil {
		logger.Info(err)
		return httpError{status: http.StatusInternalServerError, message: fmt.Sprintf("Was not able to delete issuer %s", id), rootError: err}
	}
	return httpErr
}

func (MySqlRepo) PutIssuer(trustedIssuer TrustedIssuer) (httpErr httpError) {

	_, httpErr = getSqlIssuer(trustedIssuer.Id)
	if httpErr != (httpError{}) {
		return httpErr
	}
	err := repo.Transaction(context.TODO(), func(ctx context.Context) error {
		deleteIssuer(trustedIssuer.Id)
		updatedIssuer := toSqlIssuer(trustedIssuer)
		return persistIssuer(updatedIssuer)
	})
	if err != nil {
		return httpError{status: http.StatusInternalServerError, message: "Was not able to update issuer.", rootError: err}
	}
	return httpErr
}

func (MySqlRepo) GetIssuers(limit int, offset int) (trustedIssuers []TrustedIssuer, httpErr httpError) {

	var issuers []dbModel.TrustedIssuer
	err := repo.FindAll(context.TODO(), &issuers, rel.Limit(limit), rel.Offset(offset))
	if err != nil {
		return trustedIssuers, httpError{http.StatusInternalServerError, "Was not able to query for issuers.", err}
	}
	for _, issuer := range issuers {
		sqlIssuer, httpErr := getSqlIssuer(issuer.ID)
		if httpErr != (httpError{}) {
			return trustedIssuers, httpErr
		}
		trustedIssuers = append(trustedIssuers, fromSqlIssuer(sqlIssuer))
	}
	return trustedIssuers, httpErr
}
func persistIssuer(trustedIssuer dbModel.TrustedIssuer) error {
	ctx := context.TODO()

	return repo.Transaction(ctx, func(ctx context.Context) error {
		err := repo.Insert(ctx, &trustedIssuer)
		if err != nil {
			return err
		}
		for _, capability := range trustedIssuer.Capabilities {
			err = repo.Update(ctx, &capability)
			if err != nil {
				return err
			}
			for _, claim := range capability.Claims {
				err = repo.Update(ctx, &claim)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func toSqlIssuer(trustedIssuer TrustedIssuer) dbModel.TrustedIssuer {
	sqlIssuer := dbModel.TrustedIssuer{ID: trustedIssuer.Id}
	capabilities := []dbModel.Capability{}
	for _, capability := range *trustedIssuer.Capabilities {
		capabilities = append(capabilities, toSqlCapability(capability))
	}
	sqlIssuer.Capabilities = capabilities
	return sqlIssuer
}

func toSqlCapability(capability Capability) dbModel.Capability {
	sqlCapability := dbModel.Capability{ValidFrom: capability.ValidFor.From, ValidTo: capability.ValidFor.To, CredentialsType: capability.CredentialsType}
	claims := []dbModel.Claim{}
	for _, claim := range *capability.Claims {
		claims = append(claims, toSqlClaim(claim))
	}
	sqlCapability.Claims = claims
	return sqlCapability
}

func toSqlClaim(claim Claim) dbModel.Claim {
	sqlClaim := dbModel.Claim{Name: claim.Name}
	allowedValues := []dbModel.AllowedValue{}
	for _, value := range claim.AllowedValues {
		allowedValues = append(allowedValues, dbModel.AllowedValue{AllowedValue: value})
	}
	sqlClaim.AllowedValues = allowedValues
	return sqlClaim
}

func fromSqlIssuer(sqlIssuer dbModel.TrustedIssuer) TrustedIssuer {
	trustedIssuer := TrustedIssuer{Id: sqlIssuer.ID}
	capabilities := []Capability{}
	for _, capability := range sqlIssuer.Capabilities {
		capabilities = append(capabilities, fromSqlCapability(capability))
	}
	trustedIssuer.Capabilities = &capabilities
	return trustedIssuer
}

func fromSqlCapability(sqlCapability dbModel.Capability) Capability {
	validFor := &TimeRange{From: sqlCapability.ValidFrom, To: sqlCapability.ValidTo}
	capability := Capability{ValidFor: validFor, CredentialsType: sqlCapability.CredentialsType}
	claims := []Claim{}
	for _, claim := range sqlCapability.Claims {
		claims = append(claims, fromSqlClaim(claim))
	}
	capability.Claims = &claims
	return capability
}

func fromSqlClaim(sqlClaim dbModel.Claim) Claim {
	claim := Claim{Name: sqlClaim.Name}
	allowedValues := []string{}
	for _, allowedValue := range sqlClaim.AllowedValues {
		allowedValues = append(allowedValues, allowedValue.AllowedValue)
	}
	claim.AllowedValues = allowedValues
	return claim
}
