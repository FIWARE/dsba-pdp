package decision

import (
	"net/http"
	"sort"
	"testing"
	"time"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
)

type mockConfig struct {
	providerId string
}

func (mc mockConfig) ProviderId() string {
	return mc.providerId
}

type mockRegistry struct {
	mockEvidence      model.DelegationEvidence
	mockError         model.HttpError
	requestedPolicies *[]model.Policy
}

func (mr *mockRegistry) GetPDPRegistry() *model.AuthorizationRegistry {
	return &model.AuthorizationRegistry{}
}

func (mr *mockRegistry) getRequestedPolicies() []model.Policy {
	if mr.requestedPolicies != nil {
		return *mr.requestedPolicies
	}
	return []model.Policy{}
}

func (mr *mockRegistry) GetDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]model.Policy, authorizationRegistry *model.AuthorizationRegistry) (delegeationEvidence *model.DelegationEvidence, httpErr model.HttpError) {
	logger.Debugf("Return evidence %s and error %s.", logging.PrettyPrintObject(mr.mockEvidence), logging.PrettyPrintObject(mr.mockError))
	mr.requestedPolicies = requiredPolicies
	return &mr.mockEvidence, mr.mockError
}

type mockClock struct{}

func (c mockClock) Now() time.Time {
	logger.Info("Return now")
	// stay on 23-12-2021 so that the cert chain is still valid
	return time.Unix(1640272719, 0)
}

func TestDecide(t *testing.T) {

	// run tests with debug logging
	logging.Log().SetLevel(logrus.DebugLevel)

	type test struct {
		testName         string
		testToken        model.DSBAToken
		testAddress      string
		testRequestType  string
		testRequestBody  *map[string]interface{}
		testProviderId   string
		mockEvidence     model.DelegationEvidence
		mockError        model.HttpError
		expectedDecision model.Decision
		expectedError    model.HttpError
		expectedPolicies []model.Policy
	}

	tests := []test{

		{"Allow GET request when permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Allow POST request when permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Allow DELETE request when permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Allow PUT request when permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Allow PATCH request when permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Allow GET request for iShareTokens when permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Allow POST request for iShareTokens when permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Allow DELETE request for iShareTokens when permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Allow PUT request for iShareTokens when permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Allow PATCH request for iShareTokens when permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Requests without a role should be denied.", getNoRoleDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{}},

		{"Deny GET request when no permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when no permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when no permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when no permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when no permit is answered.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Deny GET request when permit is not active anymore.", getDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when permit is not active anymore.", getDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when permit is not active anymore.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when permit is not active anymore.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when permit is not active anymore.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Deny GET request when permit is not active yet.", getDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when permit is not active yet.", getDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when permit is not active yet.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when permit is not active yet.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when permit is not active yet.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"GET request with AR error should bubble.", getDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"POST request with AR error should bubble.", getDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"DELETE request with AR error should bubble.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"PUT request with AR error should bubble.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"PATCH request with AR error should bubble.", getDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Deny GET request when no permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when no permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when no permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when no permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when no permit is answered.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getActiveDeny(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Deny GET request when permit is not active anymore.", getIShareDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when permit is not active anymore.", getIShareDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when permit is not active anymore.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when permit is not active anymore.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when permit is not active anymore.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getAfterPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Deny GET request when permit is not active yet.", getIShareDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"Deny POST request when permit is not active yet.", getIShareDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"Deny DELETE request when permit is not active yet.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"Deny PUT request when permit is not active yet.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"Deny PATCH request when permit is not active yet.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", getNotYetPermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"GET request with AR error should bubble.", getIShareDSBAToken(), "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("ENTITY", []string{"*"}, []string{"*"}, "GET")}},
		{"POST request with AR error should bubble.", getIShareDSBAToken(), "/ngsi-ld/v1/entities", "POST", getEntity(), "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"*"}, []string{"id", "myProp"}, "POST")}},
		{"DELETE request with AR error should bubble.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-delete", "DELETE", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-delete"}, []string{"*"}, "DELETE")}},
		{"PUT request with AR error should bubble.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-put", "PUT", nil, "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-put"}, []string{"*"}, "PUT")}},
		{"PATCH request with AR error should bubble.", getIShareDSBAToken(), "/ngsi-ld/v1/entities/urn:ngsi-ld:entity:to-patch", "PATCH", getEntity(), "myPdp", model.DelegationEvidence{}, getBadGatewayError(), model.Decision{}, getBadGatewayError(), []model.Policy{getPolicy("entity", []string{"urn:ngsi-ld:entity:to-patch"}, []string{"id", "myProp"}, "PATCH")}},

		{"Non-NGSI GET requests are considered a BadRequest.", getDSBAToken(), "/non/ngsi/request", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
		{"Non-NGSI POST requests are considered a BadRequest.", getDSBAToken(), "/non/ngsi/request", "POST", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
		{"Non-NGSI PUT requests are considered a BadRequest.", getDSBAToken(), "/non/ngsi/request", "PUT", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
		{"Non-NGSI DELETE requests are considered a BadRequest.", getDSBAToken(), "/non/ngsi/request", "DELETE", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
		{"Non-NGSI PATCH requests are considered a BadRequest.", getDSBAToken(), "/non/ngsi/request", "PATCH", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},

		{"NGSI-GET requests without a type are considered a BadRequest.", getDSBAToken(), "/ngsi-ld/v1/entities", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
		{"NGSI-GET requests on non ngis-entities are considered a BadRequest.", getDSBAToken(), "/ngsi-ld/v1/entities/myEntity", "GET", nil, "myPdp", getActivePermit(), model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 400}, []model.Policy{}},
	}

	for _, tc := range tests {
		logger.Infof("TestDecide +++++++++++++++++ Running test: %s", tc.testName)
		mr := mockRegistry{mockEvidence: tc.mockEvidence, mockError: tc.mockError}
		decider := NewIShareDecider(&mr, mockConfig{providerId: tc.testProviderId})
		logger.Debugf("Test path %s", tc.testAddress)
		decision, httpErr := decider.Decide(&tc.testToken, tc.testAddress, tc.testRequestType, tc.testRequestBody)
		if httpErr.Status != tc.expectedError.Status {
			t.Errorf("%s: Unexpected error on decision. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(httpErr))
		}
		if decision.Decision != tc.expectedDecision.Decision {
			t.Errorf("%s: Unexpected decision. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedDecision), logging.PrettyPrintObject(decision))
		}

		if !equalPolicies(tc.expectedPolicies, mr.getRequestedPolicies()) {
			t.Errorf("%s: Unexpected policies requested. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedPolicies), logging.PrettyPrintObject(mr.getRequestedPolicies()))
		}
	}

}

func getBadGatewayError() model.HttpError {
	return model.HttpError{Status: http.StatusBadGateway}
}

func getNoRoleDSBAToken() model.DSBAToken {
	return model.DSBAToken{
		VerifiableCredential: model.DSBAVerifiableCredential{
			Issuer: "myIssuer",
			CredentialSubject: model.CredentialSubject{
				Roles: []model.Role{},
			},
		},
	}
}

func getIShareDSBAToken() model.DSBAToken {
	return model.DSBAToken{
		VerifiableCredential: model.DSBAVerifiableCredential{
			Issuer: "myIssuer",
			CredentialSubject: model.CredentialSubject{
				Roles: []model.Role{
					{Name: []string{"CUSTOMER"}, Target: "myPdp"},
				},
				IShareCredentialsSubject: &model.IShareCredentialsSubject{
					AuthorizationRegistries: &map[string]model.AuthorizationRegistry{
						"myAr": {
							Host: "ar.org",
						},
					},
				},
			},
		},
	}
}

func getDSBAToken() model.DSBAToken {
	return model.DSBAToken{
		VerifiableCredential: model.DSBAVerifiableCredential{
			Issuer: "myIssuer",
			CredentialSubject: model.CredentialSubject{
				Roles: []model.Role{
					{Name: []string{"CUSTOMER"}, Target: "myPdp"},
				},
			},
		},
	}
}

func getActiveDeny() model.DelegationEvidence {
	return model.DelegationEvidence{
		// this is year 2920
		NotOnOrAfter: 30000000000,
		// this is year 1970
		NotBefore: 0,
		PolicySets: []model.PolicySet{
			{
				Policies: []model.Policy{
					{
						Rules: []model.Rule{
							{
								Effect: "Deny"},
						},
					},
				},
			},
		},
	}
}

func getAfterPermit() model.DelegationEvidence {
	return model.DelegationEvidence{
		// this is year 1970
		NotOnOrAfter: 1000,
		// this is year 1970
		NotBefore: 0,
		PolicySets: []model.PolicySet{
			{
				Policies: []model.Policy{
					{
						Rules: []model.Rule{
							{
								Effect: "Permit"},
						},
					},
				},
			},
		},
	}
}

func getNotYetPermit() model.DelegationEvidence {
	return model.DelegationEvidence{
		// this is year 2920
		NotOnOrAfter: 30000000000,
		// this is year 2920
		NotBefore: 29990000000,
		PolicySets: []model.PolicySet{
			{
				Policies: []model.Policy{
					{
						Rules: []model.Rule{
							{
								Effect: "Permit"},
						},
					},
				},
			},
		},
	}
}

func getActivePermit() model.DelegationEvidence {
	return model.DelegationEvidence{
		NotOnOrAfter: 300000000000,
		NotBefore:    0,
		PolicySets: []model.PolicySet{
			{
				Policies: []model.Policy{
					{
						Rules: []model.Rule{
							{
								Effect: "Permit"},
						},
					},
				},
			},
		},
	}
}

func getEntity() *map[string]interface{} {
	entity := map[string]interface{}{
		"id":   "urn:ngsi-ld:entity:id",
		"type": "entity",
		"myProp": struct {
			propertyType string
			price        float64
		}{"property", 1.75},
	}
	return &entity
}

func getPolicy(entityType string, identifiers []string, attributes []string, request string) model.Policy {
	return model.Policy{
		Target: &model.PolicyTarget{
			Resource: &model.Resource{
				Type:        entityType,
				Identifiers: identifiers,
				Attributes:  attributes,
			},
			Actions: []string{request},
		},
		Rules: []model.Rule{
			{
				Effect: "Permit",
			},
		},
	}
}

func equalPolicies(a, b []model.Policy) bool {
	if len(a) != len(b) {
		logger.Debugf("Policy strings have different length.")
		return false
	}

	for i, v := range a {
		// since only attributes can contain multiple multiple values, we order them "manually"
		// if thats not done, the test becomes flaky, since the comparison function checks the order of a slice, while its not important for functionality
		sort.Strings(v.Target.Resource.Attributes)
		sort.Strings(b[i].Target.Resource.Attributes)
		if !cmp.Equal(v, b[i]) {
			logger.Debugf("%s is not equal to %s", logging.PrettyPrintObject(v), logging.PrettyPrintObject(b[i]))
			return false
		}
	}
	return true
}
