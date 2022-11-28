package decision

import (
	"testing"

	"github.com/sirupsen/logrus"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

type mockConfig struct {
	providerId string
}

func (mc mockConfig) ProviderId() string {
	return mc.providerId
}

type mockRegistry struct {
	mockEvidence model.DelegationEvidence
	mockError    model.HttpError
}

func (mr mockRegistry) GetPDPRegistry() *model.AuthorizationRegistry {
	return &model.AuthorizationRegistry{}
}

func (mr mockRegistry) GetDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]model.Policy, authorizationRegistry *model.AuthorizationRegistry) (delegeationEvidence *model.DelegationEvidence, httpErr model.HttpError) {
	logger.Debugf("Return evidence %s and error %s.", logging.PrettyPrintObject(mr.mockEvidence), logging.PrettyPrintObject(mr.mockError))
	return &mr.mockEvidence, mr.mockError
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
	}

	tests := []test{
		{
			"", model.DSBAToken{VerifiableCredential: model.DSBAVerifiableCredential{Issuer: "myIssuer", CredentialSubject: model.CredentialSubject{Roles: []model.Role{{Name: []string{"CUSTOMER"}, Target: "myPdp"}}}}}, "/ngsi-ld/v1/entities?type=ENTITY", "GET", nil, "myPdp", model.DelegationEvidence{NotOnOrAfter: 300000000000, NotBefore: 0, PolicySets: []model.PolicySet{{Policies: []model.Policy{{Rules: []model.Rule{{Effect: "Permit"}}}}}}}, model.HttpError{}, model.Decision{Decision: true}, model.HttpError{},
		},
	}

	for _, tc := range tests {
		logger.Infof("TestDecide +++++++++++++++++ Running test: %s", tc.testName)

		decider := NewIShareDecider(mockRegistry{mockEvidence: tc.mockEvidence, mockError: tc.mockError}, mockConfig{providerId: tc.testProviderId})
		decision, httpErr := decider.Decide(&tc.testToken, tc.testAddress, tc.testRequestType, tc.testRequestBody)
		if httpErr.Status != tc.expectedError.Status {
			t.Errorf("%s: Unexpected error on decision. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(httpErr))
		}
		if decision.Decision != tc.expectedDecision.Decision {
			t.Errorf("%s: Unexpected decision. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedDecision), logging.PrettyPrintObject(decision))
		}
	}

}
