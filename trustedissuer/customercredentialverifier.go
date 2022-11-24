package trustedissuer

import (
	"fmt"

	"github.com/wistefan/dsba-pdp/config"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

var logger = logging.Log()
var providerId = config.ProviderId()

type CustomerCredentialVerifier struct{}

func (CustomerCredentialVerifier) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject) (descision model.Decision, err model.HttpError) {

	// check that no addtional information is included

	if credentialSubject.IShareCredentialsSubject != nil {
		return model.Decision{false, fmt.Sprintf("The credential %s includes forbidden claims.", logging.PrettyPrintObject(*credentialSubject))}, err
	}
	return CheckRoles(claims, credentialSubject)
}

func CheckRoles(claims *[]model.Claim, credentialSubject *model.CredentialSubject) (descision model.Decision, err model.HttpError) {
	roleClaim := model.Claim{}
	for _, claim := range *claims {
		if claim.Name == "roles" {
			roleClaim = claim
			break
		}
	}
	if roleClaim.Name == "" {
		return model.Decision{true, "No restrictions for roles exist."}, err
	}

	if len(roleClaim.AllowedValues) == 0 {
		return model.Decision{false, fmt.Sprintf("Claim %s does not allow any role assignment.", logging.PrettyPrintObject(roleClaim))}, err
	}

	for _, role := range credentialSubject.Roles {
		if role.Target == providerId {
			descision = isRoleAllowed(role.Name, roleClaim)
			if !descision.Decision {
				return descision, err
			}
		}
	}
	return model.Decision{true, "Role claims allowed."}, err
}

func isRoleAllowed(roleNames []string, roleClaim model.Claim) (decision model.Decision) {
	for _, roleName := range roleNames {
		if !contains(roleClaim.AllowedValues, roleName) {
			return model.Decision{false, fmt.Sprintf("Role %s is not coverd by the roles-claim capability %s.", roleName, logging.PrettyPrintObject(roleClaim))}

		}
	}
	return model.Decision{true, "Roles allowed."}
}
