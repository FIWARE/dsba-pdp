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
