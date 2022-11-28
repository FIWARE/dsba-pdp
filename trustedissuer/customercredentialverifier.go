package trustedissuer

import (
	"fmt"

	"github.com/wistefan/dsba-pdp/config"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

const ROLES_KEY = "roles"

var logger = logging.Log()
var envConfig config.Config = config.EnvConfig{}

type CustomerCredentialVerifier struct{}

func (CustomerCredentialVerifier) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject) (descision model.Decision, err model.HttpError) {

	// check that no addtional information is included

	if credentialSubject.IShareCredentialsSubject != nil {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("The credential %s includes forbidden claims.", logging.PrettyPrintObject(*credentialSubject))}, err
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
		return model.Decision{Decision: true, Reason: "No restrictions for roles exist."}, err
	}

	if len(roleClaim.AllowedValues) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("Claim %s does not allow any role assignment.", logging.PrettyPrintObject(roleClaim))}, err
	}

	for _, role := range credentialSubject.Roles {
		if role.Target == envConfig.ProviderId() {
			descision = isRoleAllowed(role.Name, roleClaim)
			if !descision.Decision {
				return descision, err
			}
		}
	}
	return model.Decision{Decision: true, Reason: "Role claims allowed."}, err
}

func isRoleAllowed(roleNames []string, roleClaim model.Claim) (decision model.Decision) {
	allowedRoles := []string{}
	for _, allowedValue := range roleClaim.AllowedValues {
		if allowedValue.String != "" {
			allowedRoles = append(allowedRoles, allowedValue.String)
		}
		if allowedValue.RoleValue != (model.RoleValue{}) && allowedValue.RoleValue.Name != nil {
			allowedRoles = append(allowedRoles, *allowedValue.RoleValue.Name...)
		}
	}
	for _, roleName := range roleNames {
		if !contains(allowedRoles, roleName) {
			return model.Decision{Decision: false, Reason: fmt.Sprintf("Role %s is not coverd by the roles-claim capability %s.", roleName, logging.PrettyPrintObject(roleClaim))}

		}
	}
	return model.Decision{Decision: true, Reason: "Roles allowed."}
}
