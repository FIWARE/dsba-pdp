package trustedissuer

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	"github.com/go-rel/mysql"
	"github.com/go-rel/rel"
	"github.com/go-rel/rel/where"
	_ "github.com/go-sql-driver/mysql"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
	dbModel "github.com/wistefan/dsba-pdp/sql"
)

type SqlRepo struct {
	repo *rel.Repository
}

func GetMySqlRepository() rel.Repository {
	var err error

	mysqlHost := os.Getenv("MYSQL_HOST")
	if mysqlHost == "" {
		logger.Fatalf("No mysql host configured, mysql repo not available.")
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
		logger.Fatal("No mysql db configured, mysql repo not available.")
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
		logger.Fatalf("Was not able to connect to db: %s:%d/%s as user %s. Err: %v", mysqlHost, mySqlPort, mysqlDb, mysqlUser, err)
	}
	return rel.New(adapter)
}

func NewSqlRepository(repository rel.Repository) *SqlRepo {

	sqlRepo := new(SqlRepo)
	sqlRepo.repo = &repository
	return sqlRepo
}

func (sqlRepo SqlRepo) CreateIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {
	if trustedIssuer.Id == "" {
		logger.Infof("Failed to create issuer %s because of missing id.", logging.PrettyPrintObject(trustedIssuer))
		return model.HttpError{Status: http.StatusBadRequest, Message: "Issuer id is required.", RootError: nil}
	}

	err := (*sqlRepo.repo).Find(context.TODO(), &dbModel.TrustedIssuer{}, where.Eq("id", trustedIssuer.Id))
	if err == nil {
		logger.Debugf("Issuer %s already exists", trustedIssuer.Id)
		return model.HttpError{Status: http.StatusConflict, Message: "Issuer already exists.", RootError: nil}
	}
	logger.Infof("Error was %v", err.Error())

	sqlIssuer := toSqlIssuer(trustedIssuer)
	logger.Infof("Issuer %s", logging.PrettyPrintObject(sqlIssuer))
	err = sqlRepo.persistIssuer(sqlIssuer)
	if err != nil {
		return model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to store issuer.", RootError: err}
	}

	return httpErr
}

func (sqlRepo SqlRepo) GetIssuer(id string) (trustedIssuer model.TrustedIssuer, httpErr model.HttpError) {

	sqlIssuer, httpErr := sqlRepo.getSqlIssuer(id)
	if httpErr != (model.HttpError{}) {
		return trustedIssuer, httpErr
	}
	return fromSqlIssuer(sqlIssuer), httpErr
}

func (sqlRepo SqlRepo) getSqlIssuer(id string) (trustedIssuer dbModel.TrustedIssuer, httpErr model.HttpError) {
	ctx := context.TODO()

	var dbIssuer dbModel.TrustedIssuer = dbModel.TrustedIssuer{}
	err := (*sqlRepo.repo).Find(ctx, &dbIssuer, where.Eq("id", id))
	if err != nil {
		return trustedIssuer, model.HttpError{Status: http.StatusNotFound, Message: fmt.Sprintf("Issuer %s not found.", id), RootError: nil}
	}
	logger.Debugf("Found issuer %s.", logging.PrettyPrintObject(dbIssuer))
	loadedCapabilities := []dbModel.Capability{}
	for _, capability := range dbIssuer.Capabilities {
		err = (*sqlRepo.repo).Find(ctx, &capability, where.Eq("id", capability.ID))
		if err != nil {
			return trustedIssuer, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to load claims.", RootError: err}
		}
		loadedClaims := []dbModel.Claim{}
		for _, claim := range capability.Claims {
			err = (*sqlRepo.repo).Find(ctx, &claim, where.Eq("id", claim.ID))
			if err != nil {
				return trustedIssuer, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to load allowed values.", RootError: err}
			}
			loadedClaims = append(loadedClaims, claim)
		}
		capability.Claims = loadedClaims
		loadedCapabilities = append(loadedCapabilities, capability)
	}
	dbIssuer.Capabilities = loadedCapabilities
	return dbIssuer, httpErr
}

func (sqlRepo SqlRepo) DeleteIssuer(id string) (httpErr model.HttpError) {
	sqlIssuer, httpErr := sqlRepo.getSqlIssuer(id)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Issuer %s to delete not found.", id)
		return httpErr
	}
	logger.Debugf("Deleting %s.", logging.PrettyPrintObject(sqlIssuer))
	ctx := context.TODO()

	err := (*sqlRepo.repo).Transaction(ctx, func(ctx context.Context) error {
		for _, capability := range sqlIssuer.Capabilities {
			for _, claim := range capability.Claims {
				for _, allowedValue := range claim.AllowedValues {
					err := (*sqlRepo.repo).Delete(ctx, &allowedValue)
					if err != nil {
						logger.Infof("Was not able to delete allowedValue %d", allowedValue.ID)
						return err
					}
				}
				err := (*sqlRepo.repo).Delete(ctx, &claim)
				if err != nil {
					logger.Infof("Was not able to delete claim %d", claim.ID)
					return err
				}
			}
			err := (*sqlRepo.repo).Delete(ctx, &capability)
			if err != nil {
				logger.Infof("Was not able to delete capability %d", capability.ID)
				return err
			}
		}
		return (*sqlRepo.repo).Delete(ctx, &sqlIssuer)
	})

	if err != nil {
		return model.HttpError{Status: http.StatusInternalServerError, Message: fmt.Sprintf("Was not able to delete issuer %s", id), RootError: err}
	}
	return httpErr
}

func (sqlRepo SqlRepo) PutIssuer(trustedIssuer model.TrustedIssuer) (httpErr model.HttpError) {

	_, httpErr = sqlRepo.getSqlIssuer(trustedIssuer.Id)
	if httpErr != (model.HttpError{}) {
		return httpErr
	}
	err := (*sqlRepo.repo).Transaction(context.TODO(), func(ctx context.Context) error {
		sqlRepo.DeleteIssuer(trustedIssuer.Id)
		updatedIssuer := toSqlIssuer(trustedIssuer)
		return sqlRepo.persistIssuer(updatedIssuer)
	})
	if err != nil {
		return model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to update issuer.", RootError: err}
	}
	return httpErr
}

func (sqlRepo SqlRepo) GetIssuers(limit int, offset int) (trustedIssuers []model.TrustedIssuer, httpErr model.HttpError) {

	var issuers []dbModel.TrustedIssuer
	err := (*sqlRepo.repo).FindAll(context.TODO(), &issuers, rel.Limit(limit), rel.Offset(offset))
	if err != nil {
		return trustedIssuers, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to query for issuers.", RootError: err}
	}
	for _, issuer := range issuers {
		sqlIssuer, httpErr := sqlRepo.getSqlIssuer(issuer.ID)
		if httpErr != (model.HttpError{}) {
			return trustedIssuers, httpErr
		}
		trustedIssuers = append(trustedIssuers, fromSqlIssuer(sqlIssuer))
	}
	return trustedIssuers, httpErr
}
func (sqlRepo SqlRepo) persistIssuer(trustedIssuer dbModel.TrustedIssuer) error {
	ctx := context.TODO()

	return (*sqlRepo.repo).Transaction(ctx, func(ctx context.Context) error {
		logger.Debugf("Start insert transaction for %s", logging.PrettyPrintObject(trustedIssuer))
		err := (*sqlRepo.repo).Insert(ctx, &trustedIssuer)
		if err != nil {
			logger.Debugf("Was not able to insert the issuer. Error was: %v", err)
			return err
		}
		for _, capability := range trustedIssuer.Capabilities {
			err = (*sqlRepo.repo).Update(ctx, &capability)
			if err != nil {
				return err
			}
			for _, claim := range capability.Claims {
				err = (*sqlRepo.repo).Update(ctx, &claim)
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
}

func toSqlIssuer(trustedIssuer model.TrustedIssuer) dbModel.TrustedIssuer {
	sqlIssuer := dbModel.TrustedIssuer{ID: trustedIssuer.Id}
	capabilities := []dbModel.Capability{}
	for _, capability := range *trustedIssuer.Capabilities {
		capabilities = append(capabilities, toSqlCapability(capability))
	}
	sqlIssuer.Capabilities = capabilities
	return sqlIssuer
}

func toSqlCapability(capability model.Capability) dbModel.Capability {
	sqlCapability := dbModel.Capability{ValidFrom: capability.ValidFor.From, ValidTo: capability.ValidFor.To, CredentialsType: capability.CredentialsType}
	claims := []dbModel.Claim{}
	for _, claim := range *capability.Claims {
		claims = append(claims, toSqlClaim(claim))
	}
	sqlCapability.Claims = claims
	return sqlCapability
}

func toSqlClaim(claim model.Claim) dbModel.Claim {
	sqlClaim := dbModel.Claim{Name: claim.Name}
	allowedValues := []dbModel.AllowedValue{}

	if claim.AllowedValues == nil {
		return sqlClaim
	}
	for _, value := range *claim.AllowedValues {
		if v, err := value.AsAllowedValuesStringValue(); err == nil && v != "" {
			allowedValues = append(allowedValues, dbModel.AllowedValue{AllowedString: v})
		}
		if v, err := value.AsAllowedValuesRoleValue(); err == nil && v != (model.RoleValue{}) {
			roleValueString, _ := json.Marshal(dbModel.AllowedRole{Name: *v.Name, ProviderId: v.ProviderId})
			allowedValues = append(allowedValues, dbModel.AllowedValue{AllowedRolevalue: string(roleValueString)})
		}
	}
	sqlClaim.AllowedValues = allowedValues
	return sqlClaim
}

func fromSqlIssuer(sqlIssuer dbModel.TrustedIssuer) model.TrustedIssuer {
	trustedIssuer := model.TrustedIssuer{Id: sqlIssuer.ID}
	capabilities := []model.Capability{}
	for _, capability := range sqlIssuer.Capabilities {
		capabilities = append(capabilities, fromSqlCapability(capability))
	}
	trustedIssuer.Capabilities = &capabilities
	return trustedIssuer
}

func fromSqlCapability(sqlCapability dbModel.Capability) model.Capability {
	validFor := &model.TimeRange{From: sqlCapability.ValidFrom, To: sqlCapability.ValidTo}
	capability := model.Capability{ValidFor: validFor, CredentialsType: sqlCapability.CredentialsType}
	claims := []model.Claim{}
	for _, claim := range sqlCapability.Claims {
		claims = append(claims, fromSqlClaim(claim))
	}
	capability.Claims = &claims
	return capability
}

func fromSqlClaim(sqlClaim dbModel.Claim) model.Claim {
	claim := model.Claim{Name: sqlClaim.Name}
	allowedValues := []model.AllowedValue{}
	for _, allowedValue := range sqlClaim.AllowedValues {
		if allowedValue.AllowedString != "" {
			stringValue := model.AllowedValue{}
			err := stringValue.FromClaimAllowedValuesStringValue(allowedValue.AllowedString)
			if err != nil {
				logger.Warnf("Value %s could not be mapped to an allowed string value. Err: %v", allowedValue.AllowedString, err)
				continue
			}
			allowedValues = append(allowedValues, stringValue)
		}
		if allowedValue.AllowedRolevalue != "" {
			roleValue := model.AllowedValue{}
			allowedRole := dbModel.AllowedRole{}
			json.Unmarshal([]byte(allowedValue.AllowedRolevalue), &allowedRole)

			err := roleValue.FromClaimAllowedValuesRoleValue(model.RoleValue{Name: &allowedRole.Name, ProviderId: allowedRole.ProviderId})
			if err != nil {
				logger.Warnf("Value %s could not be mapped to an allowed role value. Err: %v", allowedValue.AllowedRolevalue, err)
				continue
			}

			allowedValues = append(allowedValues, roleValue)
		}
	}
	claim.AllowedValues = &allowedValues
	return claim
}
