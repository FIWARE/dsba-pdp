package trustedissuer

import (
	"testing"

	log "github.com/sirupsen/logrus"
	"github.com/wistefan/dsba-pdp/model"
)

func TestCheckRoles(t *testing.T) {
	type test struct {
		testName         string
		testClaims       []model.Claim
		testSubject      model.CredentialSubject
		expectedDecision bool
		expectedError    model.HttpError
	}

	tests := []test{
		{"Allow subjects if not claim is configured.", []model.Claim{}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{}}, true, model.HttpError{}},
		{"Allow subjects if only other claims are configured.", []model.Claim{{Name: "OTHER_CLAIM", AllowedValues: []model.AllowedValue{{String: "CUSTOMER"}}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{}}, true, model.HttpError{}},
		//{"Allow subjects if claim allows the assigned role.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []model.AllowedValue{"CUSTOMER"}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, true, model.HttpError{}},
		//{"Allow if more roles are allowed.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []string{"CUSTOMER", "EMPLOYEE"}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"EMPLOYEE"}}}}, true, model.HttpError{}},
		//{"Reject if claim has empty allowed values.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []string{}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, false, model.HttpError{}},
		//{"Reject if claim has different role allowed values.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []string{"EMPLOYEE"}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER"}}}}, false, model.HttpError{}},
		//{"Reject if subject has additional roles.", []model.Claim{{Name: ROLES_KEY, AllowedValues: []string{"EMPLOYEE"}}}, model.CredentialSubject{Id: "mySubject", Roles: []model.Role{{Name: []string{"CUSTOMER", "EMPLOYEE"}}}}, false, model.HttpError{}},
	}

	for _, tc := range tests {
		log.Info("TestCheckRoles +++++++++++++++++ Running test: ", tc.testName)
		decision, err := CheckRoles(&tc.testClaims, &tc.testSubject)
		if err != (model.HttpError{}) && err != tc.expectedError {
			t.Errorf("%s: Role check returned an unexpected err. Expected: %v, Actual: %v", tc.testName, tc.expectedError, err)
		}
		if decision.Decision != tc.expectedDecision {
			t.Errorf("%s: Role check returned wrong decision. Expected: %v, Actual: %v", tc.testName, tc.expectedDecision, decision)
		}
	}
}
