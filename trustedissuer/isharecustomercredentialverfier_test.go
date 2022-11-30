package trustedissuer

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

func TestIShareVerify(t *testing.T) {

	type test struct {
		testName         string
		testClaims       []model.Claim
		testSubject      model.CredentialSubject
		testIssuerId     string
		expectedDecision bool
		expectedError    model.HttpError
	}

	tests := []test{
		{"Allow subjects if no role claim is configured.", []model.Claim{}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if only other claims are configured.", []model.Claim{{Name: "OTHER_CLAIM", AllowedValues: []model.AllowedValue{{String: "CUSTOMER"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if claim allows the assigned role.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{String: "CUSTOMER"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow if more roles are allowed.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{String: "CUSTOMER"}, {String: "EMPLOYEE"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"EMPLOYEE"}}}}, "did:test:issuer", true, model.HttpError{}},
		{"Reject if claim has empty allowed values.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, "did:test:issuer", false, model.HttpError{}},
		{"Reject if claim has different role allowed values.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{String: "EMPLOYEE"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, "did:test:issuer", false, model.HttpError{}},
		{"Reject if subject has additional roles.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{String: "EMPLOYEE"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER", "EMPLOYEE"}}}}, "did:test:issuer", false, model.HttpError{}},

		{"Allow subjects if no ar-claim is configured.", []model.Claim{}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:my:ar": {}}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if the ar is allowed by the claim configured.", []model.Claim{{Name: AR_KEY, AllowedValues: []model.AllowedValue{{String: "did:my:ar"}}}}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:my:ar": {}}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if the ar is one of the allowed by the claim configured.", []model.Claim{{Name: AR_KEY, AllowedValues: []model.AllowedValue{{String: "did:my:ar"}, {String: "did:another:ar"}}}}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:my:ar": {}}}}, "did:test:issuer", true, model.HttpError{}},
		{"Reject subjects if no ar is covered by the claim configured.", []model.Claim{{Name: AR_KEY, AllowedValues: []model.AllowedValue{}}}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:my:ar": {}}}}, "did:test:issuer", false, model.HttpError{}},
		{"Reject subjects if the ar is not covered by the claim configured.", []model.Claim{{Name: AR_KEY, AllowedValues: []model.AllowedValue{{String: "did:another:ar"}}}}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:my:ar": {}}}}, "did:test:issuer", false, model.HttpError{}},
		{"Reject subjects if on of the ars is not covered by the claim configured.", []model.Claim{{Name: AR_KEY, AllowedValues: []model.AllowedValue{{String: "did:my:ar"}}}}, model.CredentialSubject{Id: "mySubject", IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"did:another:ar": {}, "did:my:ar": {}}}}, "did:test:issuer", false, model.HttpError{}},

		{"Allow subjects if no role-provider-claim is configured.", []model.Claim{}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"TEST"}, Provider: "EU.EORI.HAPPYPETS", Target: "did:test:issuer"}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if role-provider is allowed by the claim.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.HAPPYPETS"}}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"TEST"}, Provider: "EU.EORI.HAPPYPETS", Target: "did:test:issuer"}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if role-provider is one of the allowed by the claim.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.HAPPYPETS"}}, {RoleValue: model.RoleValue{ProviderId: "EU.EORI.PACKETDELIVERY"}}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"TEST"}, Provider: "EU.EORI.HAPPYPETS", Target: "did:test:issuer"}}}, "did:test:issuer", true, model.HttpError{}},
		{"Reject subjects if role-provider is not of the allowed by the claim.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.PACKETDELIVERY"}}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"TEST"}, Provider: "EU.EORI.HAPPYPETS", Target: "did:test:issuer"}}}, "did:test:issuer", false, model.HttpError{}},
		{"Reject subjects if no role for the issuer is configured and the role is not allowed by the general list.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{String: "CUSTOMER"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"TEST"}, Target: "did:test:another-issuer", Provider: "EU.EORI.HAPPYPETS"}}}, "did:test:issuer", false, model.HttpError{}},

		{"Allow subjects if role and provider are allowed.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.PACKETDELIVERY", Name: &[]string{"CUSTOMER"}}}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}, Provider: "EU.EORI.PACKETDELIVERY", Target: "did:test:issuer"}}}, "did:test:issuer", true, model.HttpError{}},
		{"Allow subjects if role, provider and ar are allowed.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.PACKETDELIVERY", Name: &[]string{"CUSTOMER"}}}}}, {Name: AR_KEY, AllowedValues: []model.AllowedValue{{String: "EU.EORI.PACKETDELIVERY"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}, Provider: "EU.EORI.PACKETDELIVERY", Target: "did:test:issuer"}}, IShareCredentialsSubject: &model.IShareCredentialsSubject{AuthorizationRegistries: &map[string]model.AuthorizationRegistry{"EU.EORI.PACKETDELIVERY": {}}}}, "did:test:issuer", true, model.HttpError{}},

		{"Deny subjects if role is allowed for different provider, but provider not.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{{RoleValue: model.RoleValue{ProviderId: "EU.EORI.OTHERPROVIDER", Name: &[]string{"CUSTOMER"}}}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}, Provider: "EU.EORI.PACKETDELIVERY", Target: "did:test:issuer"}}}, "did:test:issuer", false, model.HttpError{}},
	}

	// set logging to debug on testing
	logging.Log().SetLevel(log.DebugLevel)

	for _, tc := range tests {
		log.Info("TestVerify +++++++++++++++++ Running test: ", tc.testName)
		decision, err := IShareCustomerCredentialVerifier{}.Verify(&tc.testClaims, &tc.testSubject, tc.testIssuerId)
		if err != (model.HttpError{}) && err != tc.expectedError {
			t.Errorf("%s: Role check returned an unexpected err. Expected: %v, Actual: %v", tc.testName, tc.expectedError, err)
		}
		if decision.Decision != tc.expectedDecision {
			t.Errorf("%s: Role check returned wrong decision. Expected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}
	}
}
