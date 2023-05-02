package trustedissuer

import (
	"errors"
	"net/http"
	"testing"

	"github.com/go-rel/rel"
	"github.com/go-rel/rel/where"
	"github.com/go-rel/reltest"
	log "github.com/sirupsen/logrus"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/fiware/dsba-pdp/sql"
)

func getIssuer(id string, capabilities *[]model.Capability) model.TrustedIssuer {
	return model.TrustedIssuer{Id: id, Capabilities: capabilities}
}

func getCapability(validFor *model.TimeRange, credentialType string, claims *[]model.Claim) model.Capability {
	return model.Capability{ValidFor: validFor, CredentialsType: credentialType, Claims: claims}
}

func getClaim(name string, allowedValues []model.AllowedValue) model.Claim {
	return model.Claim{Name: name, AllowedValues: &allowedValues}
}

func getTimeRange(from string, to string) *model.TimeRange {
	return &model.TimeRange{From: from, To: to}
}

type creationTest struct {
	testName      string
	testIssuer    model.TrustedIssuer
	expectedError model.HttpError
}

type retrievalTest struct {
	testName       string
	issuerId       string
	dbIssuers      []model.TrustedIssuer
	expectedIssuer model.TrustedIssuer
	expectedError  model.HttpError
}

type deletionTest struct {
	testName      string
	issuerId      string
	dbIssuers     []model.TrustedIssuer
	expectedError model.HttpError
}

func getRetrievalTests() []retrievalTest {
	return []retrievalTest{
		{"Successfully return the issuer.", "myIssuer", []model.TrustedIssuer{getIssuer("myIssuer", &[]model.Capability{})}, getIssuer("myIssuer", &[]model.Capability{}), (model.HttpError{})},
		{"Successfully return the issuer when multiple exist.", "myIssuer", []model.TrustedIssuer{getIssuer("myIssuer", &[]model.Capability{}), getIssuer("anotherIssuer", &[]model.Capability{})}, getIssuer("myIssuer", &[]model.Capability{}), (model.HttpError{})},
		{"Return a not found when non existent issuer is requested.", "myIssuer", []model.TrustedIssuer{getIssuer("otherIssuer", &[]model.Capability{})}, model.TrustedIssuer{}, (model.HttpError{Status: http.StatusNotFound})},
		{"Return a not found when no issuer exists.", "myIssuer", []model.TrustedIssuer{}, model.TrustedIssuer{}, (model.HttpError{Status: http.StatusNotFound})},
	}
}

func getDeletionTests() []deletionTest {
	return []deletionTest{
		{"Successfully delete the issuer.", "myIssuer", []model.TrustedIssuer{getIssuer("myIssuer", &[]model.Capability{})}, (model.HttpError{})},
		{"Successfully delete the issuer when multiple exist.", "myIssuer", []model.TrustedIssuer{getIssuer("myIssuer", &[]model.Capability{}), getIssuer("anotherIssuer", &[]model.Capability{})}, (model.HttpError{})},
		{"Return a not found when non existent issuer is requested.", "myIssuer", []model.TrustedIssuer{getIssuer("otherIssuer", &[]model.Capability{})}, (model.HttpError{Status: http.StatusNotFound})},
		{"Return a not found when no issuer exists.", "myIssuer", []model.TrustedIssuer{}, (model.HttpError{Status: http.StatusNotFound})},
	}
}

func getCreationTests() []creationTest {
	return []creationTest{
		{"Successfully create issuer with string claim.",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{
					getClaim("TestClaim",
						[]model.AllowedValue{getAllowedStringValue("string")})})}), model.HttpError{}},
		{"Successfully create issuer with role claim.",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{
					getClaim("TestClaim",
						[]model.AllowedValue{getAllowedStringValue("{\"providerId\":\"MyProvider\", \"name\":[\"ROLE_NAME\"]}")})})}), model.HttpError{}},
		{"Successfully create issuer with multiple roles.",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{
					getClaim("TestClaim",
						[]model.AllowedValue{getAllowedStringValue("{\"providerId\":\"MyProvider\", \"name\":[\"ROLE_NAME\", \"ANOTHER_ROLE\"]}")})})}), model.HttpError{}},
		{"Successfully create issuer with multiple allowed values.",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{
					getClaim("TestClaim", []model.AllowedValue{getAllowedStringValue("string"), getAllowedStringValue("{\"providerId\":\"MyProvider\", \"name\":[\"ROLE_NAME\", \"ANOTHER_ROLE\"]}")})})}), model.HttpError{}},
		{"Successfully create issuer with multiple claims.",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{
					getClaim("FirstClaim", []model.AllowedValue{getAllowedStringValue("string")}),
					getClaim("SecondClaim", []model.AllowedValue{getAllowedStringValue("{\"providerId\":\"MyProvider\", \"name\":[\"ROLE_NAME\", \"ANOTHER_ROLE\"]}")})})}), model.HttpError{}},
		{"Successfully create issuer with multiple capabilities",
			getIssuer("myTestIssuer", &[]model.Capability{
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "CustomerCredential", &[]model.Claim{getClaim("FirstClaim", []model.AllowedValue{getAllowedStringValue("string")})}),
				getCapability(getTimeRange("2021-21-12", "2023-21-12"), "AnotherCredential", &[]model.Claim{getClaim("AnotherClaim", []model.AllowedValue{getAllowedStringValue("string")})}),
			}), model.HttpError{}},
		{"Fail if not issuer id is provided.",
			getIssuer("", &[]model.Capability{}), model.HttpError{Status: http.StatusBadRequest, Message: "Issuers need an ID.", RootError: nil}},
	}
}

func getSqlMock() (dbMock *reltest.Repository, sqlRepo IssuerRepository) {
	dbMock = reltest.New()
	sqlRepo = NewSqlRepository(dbMock)
	return
}
func TestCreateIssuer(t *testing.T) {
	// set log level for the tests to debug
	logging.Log().SetLevel(log.DebugLevel)
	createIssuerInMemory(t, getCreationTests())
	createIssuerSql(t, getCreationTests())
}

func createIssuerSql(t *testing.T, tests []creationTest) {

	log.Infof("TestCreateIssuer ----------------- TEST ON SQL-REPO -----------------")
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {

			log.Infof("TestCreateIssuer +++++++++++++++++ Running test: %s", tc.testName)
			dbMock, sqlRepo := getSqlMock()

			if tc.expectedError != (model.HttpError{}) {
				// we do not expect anyhting in that case
			} else {
				// mapping is tested explicitly
				dbIssuer := toSqlIssuer(tc.testIssuer)
				dbMock.ExpectFind(rel.Eq("id", tc.testIssuer.Id)).Error(errors.New("no_such_issuer"))
				dbMock.ExpectTransaction(func(r *reltest.Repository) {
					r.ExpectInsert().For(&dbIssuer)
					for _, cap := range dbIssuer.Capabilities {
						r.ExpectUpdate().ForType("*sql.Capability")
						for _, cl := range cap.Claims {
							r.ExpectUpdate().ForType("*sql.Claim")
							log.Info(cl)
						}
					}
				})
			}

			httpError := sqlRepo.CreateIssuer(tc.testIssuer)

			// only test on status, to allow the reason beeing implementation specific
			if httpError.Status != tc.expectedError.Status {
				t.Errorf("%s: Issuer creation through unexpected error. Expected: %v, Actual: %v.", tc.testName, tc.expectedError, httpError)
			}

			dbMock.AssertExpectations(t)
		})
	}

	// conflict test

	log.Infof("TestCreateIssuer +++++++++++++++++ Running test: Fail on conflicting issuerId.")
	dbMock := reltest.New()
	sqlRepo := NewSqlRepository(dbMock)
	dbMock.ExpectFind(rel.Eq("id", "conflictingId")).Result(toSqlIssuer(getIssuer("conflictingId", &[]model.Capability{})))

	httpError := sqlRepo.CreateIssuer(getIssuer("conflictingId", &[]model.Capability{}))
	if httpError.Status != http.StatusConflict {
		t.Errorf("If the issuer already exists, a conflict should be thrown, but error is %v.", httpError)
	}
}

func createIssuerInMemory(t *testing.T, tests []creationTest) {

	log.Infof("TestCreateIssuer ----------------- TEST ON INMEMORY-REPO -----------------")
	for _, tc := range tests {
		t.Run(tc.testName, func(t *testing.T) {
			log.Infof("TestCreateIssuer +++++++++++++++++ Running test: %s", tc.testName)
			inMemoryRepo := NewInmemoryRepo()
			httpError := inMemoryRepo.CreateIssuer(tc.testIssuer)

			// only test on status, to allow the reason beeing implementation specific
			if httpError.Status != tc.expectedError.Status {
				t.Errorf("%s: Issuer creation through unexpected error. Expected: %v, Actual: %v.", tc.testName, tc.expectedError, httpError)
			}

			if tc.expectedError != (model.HttpError{}) {
				_, ok := (*inMemoryRepo.issuerMap)[tc.testIssuer.Id]
				if ok {
					t.Errorf("%s: The issuer should not be stored in error cases.", tc.testName)
				}
				return
			}
			trustedissuer, ok := (*inMemoryRepo.issuerMap)[tc.testIssuer.Id]
			if !ok {
				t.Errorf("%s: The issuer should have been stored, but was not.", tc.testName)
			}
			if trustedissuer != tc.testIssuer {
				t.Errorf("%s: The issuer was not stored as expected. Expected: %v, Actual: %v.", tc.testName, trustedissuer, trustedissuer)
			}
		})

	}

	// conflict test

	log.Infof("TestCreateIssuer +++++++++++++++++ Running test: Fail on conflicting issuerId.")
	inMemoryRepo := NewInmemoryRepo()
	(*inMemoryRepo.issuerMap) = map[string]model.TrustedIssuer{"conflictingId": {Id: "conflictingId"}}
	httpError := inMemoryRepo.CreateIssuer(getIssuer("conflictingId", &[]model.Capability{}))
	if httpError.Status != http.StatusConflict {
		t.Errorf("If the issuer already exists, a conflict should be thrown, but error is %v.", httpError)
	}
}

func TestGetIssuer(t *testing.T) {

	logging.Log().SetLevel(log.DebugLevel)
	testGetIssuerInMemory(t)
	testGetIssuerMySql(t)
}

func testGetIssuerInMemory(t *testing.T) {
	log.Infof("TestGetIssuer ----------------- TEST ON INMEMORY-REPO -----------------")
	for _, tc := range getRetrievalTests() {
		t.Run(tc.testName, func(t *testing.T) {
			log.Infof("TestGetIssuer +++++++++++++++++ Running test: %s", tc.testName)
			inMemoryRepo := NewInmemoryRepo()
			for _, dbIssuer := range tc.dbIssuers {
				(*inMemoryRepo.issuerMap)[dbIssuer.Id] = dbIssuer
			}
			issuer, httpErr := inMemoryRepo.GetIssuer(tc.issuerId)
			if httpErr.Status != tc.expectedError.Status {
				t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, httpErr)
			}
			expectedString := logging.PrettyPrintObject(tc.expectedIssuer)
			receivedString := logging.PrettyPrintObject(issuer)
			if expectedString != receivedString {
				t.Errorf("%s: Did not receive the expected issuer. Expected: %s, Actual: %s", tc.testName, expectedString, receivedString)
			}
		})
	}
}

func testGetIssuerMySql(t *testing.T) {
	log.Infof("TestGetIssuer ----------------- TEST ON MYSQL-REPO -----------------")
	for _, tc := range getRetrievalTests() {
		t.Run(tc.testName, func(t *testing.T) {
			log.Infof("TestGetIssuer +++++++++++++++++ Running test: %s", tc.testName)
			dbMock, sqlRepo := getSqlMock()
			reqMocked := false
			for _, dbIssuer := range tc.dbIssuers {
				dbMock.ExpectFind(rel.Eq("id", dbIssuer.Id)).Result(toSqlIssuer(dbIssuer))
				if dbIssuer.Id == tc.issuerId {
					reqMocked = true
				}
			}
			if !reqMocked {
				dbMock.ExpectFind(rel.Eq("id", tc.issuerId)).Error(errors.New("no_such_issuer"))
			}

			issuer, httpErr := sqlRepo.GetIssuer(tc.issuerId)
			if httpErr.Status != tc.expectedError.Status {
				t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, httpErr)
			}
			expectedString := logging.PrettyPrintObject(tc.expectedIssuer)
			receivedString := logging.PrettyPrintObject(issuer)
			if expectedString != receivedString {
				t.Errorf("%s: Did not receive the expected issuer. Expected: %s, Actual: %s", tc.testName, expectedString, receivedString)
			}
		})
	}
}

func TestDeleteIssuer(t *testing.T) {

	logging.Log().SetLevel(log.DebugLevel)
	testDeleteIssuerInMemory(t)
	testDeleteIssuerSql(t)
}

func testDeleteIssuerInMemory(t *testing.T) {
	log.Infof("TestDeleteIssuer ----------------- TEST ON INMEMORY-REPO -----------------")
	for _, tc := range getDeletionTests() {
		t.Run(tc.testName, func(t *testing.T) {
			log.Infof("TestDeleteIssuer +++++++++++++++++ Running test: %s", tc.testName)
			inMemoryRepo := NewInmemoryRepo()
			for _, dbIssuer := range tc.dbIssuers {
				(*inMemoryRepo.issuerMap)[dbIssuer.Id] = dbIssuer
			}
			httpErr := inMemoryRepo.DeleteIssuer(tc.issuerId)
			if httpErr.Status != tc.expectedError.Status {
				t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, httpErr)
			}
			if tc.expectedError == (model.HttpError{}) {
				_, ok := (*inMemoryRepo.issuerMap)[tc.issuerId]
				if ok {
					t.Errorf("%s: The issuer should have been deleted.", tc.testName)
				}
			}
		})
	}
}

func testDeleteIssuerSql(t *testing.T) {
	log.Infof("TestDeleteIssuer ----------------- TEST ON MYSQL-REPO -----------------")
	for _, tc := range getDeletionTests() {
		t.Run(tc.testName, func(t *testing.T) {
			log.Infof("TestDeleteIssuer +++++++++++++++++ Running test: %s", tc.testName)
			dbMock, sqlRepo := getSqlMock()
			reqMocked := false
			for _, dbIssuer := range tc.dbIssuers {
				if dbIssuer.Id == tc.issuerId {
					logger.Infof("%s: Mock get for %s", tc.testName, dbIssuer.Id)
					sqlIssuer := toSqlIssuer(dbIssuer)
					dbMock.ExpectFind(rel.Where(where.Eq("id", dbIssuer.Id))).Result(sqlIssuer)
				}
			}

			if !reqMocked {
				dbMock.ExpectFind(rel.Eq("id", tc.issuerId)).Error(errors.New("no_such_issuer"))
			}
			if tc.expectedError == (model.HttpError{}) {
				var issuer sql.TrustedIssuer
				for _, dbI := range tc.dbIssuers {
					if dbI.Id == tc.issuerId {
						issuer = toSqlIssuer(dbI)
					}
				}

				// mapping is tested explicitly
				dbMock.ExpectTransaction(func(r *reltest.Repository) {
					r.ExpectDelete().ForType("*sql.TrustedIssuer")
					for _, cap := range issuer.Capabilities {
						r.ExpectUpdate().ForType("*sql.Capability")
						for _, cl := range cap.Claims {
							r.ExpectUpdate().ForType("*sql.Claim")
							log.Info(cl)
						}
					}
				})
				dbMock.ExpectDelete().ForType("*sql.TrustedIssuer")
			}

			httpErr := sqlRepo.DeleteIssuer(tc.issuerId)
			if httpErr.Status != tc.expectedError.Status {
				t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, httpErr)
			}
		})
	}
}
