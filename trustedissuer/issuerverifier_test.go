package trustedissuer

import (
	"net/http"
	"testing"
	"time"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	log "github.com/sirupsen/logrus"
)

type mockClock struct{}

func (c *mockClock) Now() time.Time {
	logger.Debugf("Its now 02-02-2022 - Happy Groundhog day!")
	// stay on a fixed date - 02-02-2022
	return time.Unix(1643809425, 0)
}

type mockRepo struct {
	mockIssuer model.TrustedIssuer
	mockError  model.HttpError
}

func (mr *mockRepo) GetIssuer(id string) (trustedIssuer model.TrustedIssuer, httpErr model.HttpError) {
	return mr.mockIssuer, mr.mockError
}
func (mr *mockRepo) CreateIssuer(trustedIssuer model.TrustedIssuer) model.HttpError {
	return mr.mockError
}

func (mr *mockRepo) DeleteIssuer(id string) model.HttpError {
	return mr.mockError
}

func (mr *mockRepo) PutIssuer(trustedIssuer model.TrustedIssuer) model.HttpError {
	return mr.mockError
}

func (mr *mockRepo) GetIssuers(limit int, offset int) (trustedIssuers []model.TrustedIssuer, httpErr model.HttpError) {
	return trustedIssuers, httpErr
}

type iShareVerifierSpy struct {
	mockDecision model.Decision
	mockError    model.HttpError
	requested    bool
}

type customerVerifierSpy struct {
	mockError model.HttpError
	requested bool
}

func (iV *iShareVerifierSpy) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (decision model.Decision, httpErr model.HttpError) {
	iV.requested = true
	// mocking, since we dont want the external calls and test the verifier specifically
	return iV.mockDecision, iV.mockError
}

func (cV *customerVerifierSpy) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (decision model.Decision, httpErr model.HttpError) {
	cV.requested = true
	if cV.mockError != (model.HttpError{}) {
		return decision, cV.mockError
	}
	return CustomerCredentialVerifier{}.Verify(claims, credentialSubject, issuerId)
}

func TestVerify(t *testing.T) {

	logging.Log().SetLevel(log.DebugLevel)

	type test struct {
		testName             string
		testCredential       model.DSBAVerifiableCredential
		mockIssuer           model.TrustedIssuer
		mockRepoError        model.HttpError
		mockDecision         model.Decision
		mockVerifierError    model.HttpError
		expectedDecision     model.Decision
		expectedError        model.HttpError
		expectedIShare       bool
		expectedCustomerCred bool
	}

	tests := []test{
		{"If no issuer is provided, the vc should be denied.", noIssuerCredential(), model.TrustedIssuer{}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},
		{"If no issuer is configured, the vc should be denied.", validCredential(), model.TrustedIssuer{}, model.HttpError{Status: http.StatusNotFound}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: http.StatusNotFound}, false, false},
		{"If issuer has no capabilities configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer"}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},
		{"If issuer has empty capabilities configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: &[]model.Capability{}}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},
		{"If issuer has outdated capabilities configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: outdatedCapabilities()}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},
		{"If issuer has not-yet active capabilities configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: notYetActiveCapabilities()}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},

		{"If issuer has capabilities with broken from configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: brokenFromCapabilities()}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 500}, false, false},
		{"If issuer has not-yet active capabilities configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: brokenToCapabilities()}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{Status: 500}, false, false},

		{"If issuer has no capabilities for the given type configured, the vc should be denied.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: otherTypeCapabilities()}, model.HttpError{}, model.Decision{}, model.HttpError{}, model.Decision{Decision: false}, model.HttpError{}, false, false},

		{"If issuer has valid capabilities configured, the vc should be allowed.", validCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: validCapabilities()}, model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, false, true},
		{"If issuer has valid capabilities configured, the iShare vc should be allowed.", validIShareCredential(), model.TrustedIssuer{Id: "myIssuer", Capabilities: validCapabilities()}, model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, model.Decision{Decision: true}, model.HttpError{}, true, false},
	}

	for _, tc := range tests {

		log.Info("TestVerify +++++++++++++++++ Running test: ", tc.testName)
		issuerRepo = &mockRepo{tc.mockIssuer, tc.mockRepoError}
		iShareSpy := iShareVerifierSpy{tc.mockDecision, tc.mockVerifierError, false}
		ccSpy := customerVerifierSpy{tc.mockVerifierError, false}
		iShareVerifier = &iShareSpy
		customerCredentialsVerifier = &ccSpy

		clock = &mockClock{}
		verifier := FiwareVerifier{}

		decision, httpErr := verifier.Verify(tc.testCredential)

		if httpErr.Status != tc.expectedError.Status {
			t.Errorf("%s: Unexpected error. Excpected: %v, Actual: %v", tc.testName, tc.expectedError, httpErr)
		}
		if decision.Decision != tc.expectedDecision.Decision {
			t.Errorf("%s: Unexpected decision. Excpected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}
		if tc.expectedIShare != iShareSpy.requested {
			t.Errorf("%s: IShare spy was not requested as it was expected. Expected: %v, Actual: %v", tc.testName, tc.expectedIShare, iShareSpy.requested)
		}
		if tc.expectedCustomerCred != ccSpy.requested {
			t.Errorf("%s: Customer credentials spy was not requested as it was expected. Expected: %v, Actual: %v", tc.testName, tc.expectedCustomerCred, ccSpy.requested)
		}
	}
}

func brokenFromCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "broken",
				// before the mocked time
				To: "2023-07-21T17:32:28Z",
			},
			CredentialsType: "CustomerCredential",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func brokenToCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "2022-07-21T17:32:28Z",
				// before the mocked time
				To: "broken",
			},
			CredentialsType: "CustomerCredential",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func notYetActiveCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "2022-07-21T17:32:28Z",
				// before the mocked time
				To: "2023-07-21T17:32:28Z",
			},
			CredentialsType: "CustomerCredential",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func outdatedCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "2017-07-21T17:32:28Z",
				// before the mocked time
				To: "2020-07-21T17:32:28Z",
			},
			CredentialsType: "CustomerCredential",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func otherTypeCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "2017-07-21T17:32:28Z",
				// after the mocked time
				To: "2023-07-21T17:32:28Z",
			},
			CredentialsType: "OtherType",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func validCapabilities() *[]model.Capability {
	caps := []model.Capability{
		{
			ValidFor: &model.TimeRange{
				// before the mocked time
				From: "2017-07-21T17:32:28Z",
				// after the mocked time
				To: "2023-07-21T17:32:28Z",
			},
			CredentialsType: "CustomerCredential",
			Claims:          validClaims(),
		},
	}
	return &caps
}

func validClaims() *[]model.Claim {
	claims := []model.Claim{
		{
			Name: "roles",
			AllowedValues: &[]model.AllowedValue{
				{
					Union: []byte("MY_ROLE"),
				},
			},
		},
	}
	return &claims
}

func noIssuerCredential() model.DSBAVerifiableCredential {
	return model.DSBAVerifiableCredential{
		Type:         []string{"CustomerCredential", "VerifiableCredential"},
		IssuanceDate: "2022-11-23T15:23:13Z",
		CredentialSubject: model.CredentialSubject{
			Id: "did:elsi:cs",
			IShareCredentialsSubject: &model.IShareCredentialsSubject{
				Roles: []model.Role{
					{
						Names:  []string{"MY_ROLE"},
						Target: "did:my:pdp",
					},
				},
			},
		},
	}
}

func validCredential() model.DSBAVerifiableCredential {
	return model.DSBAVerifiableCredential{
		Type:         []string{"CustomerCredential", "VerifiableCredential"},
		Issuer:       "did:my:issuer",
		IssuanceDate: "2022-11-23T15:23:13Z",
		CredentialSubject: model.CredentialSubject{
			Id: "did:elsi:cs",
			IShareCredentialsSubject: &model.IShareCredentialsSubject{
				Roles: []model.Role{
					{
						Names:  []string{"MY_ROLE"},
						Target: "did:my:pdp",
					},
				},
			},
		},
	}
}

func validIShareCredential() model.DSBAVerifiableCredential {
	return model.DSBAVerifiableCredential{
		Type:         []string{"CustomerCredential", "VerifiableCredential"},
		Issuer:       "did:my:issuer",
		IssuanceDate: "2022-11-23T15:23:13Z",
		CredentialSubject: model.CredentialSubject{
			Id: "did:elsi:cs",
			IShareCredentialsSubject: &model.IShareCredentialsSubject{
				AuthorizationRegistries: &map[string]model.AuthorizationRegistry{
					"AR": {Host: "my.other.ar"},
				},
				Roles: []model.Role{
					{
						Names:  []string{"MY_ROLE"},
						Target: "did:my:pdp",
					},
				},
			},
		},
	}
}
