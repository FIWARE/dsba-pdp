package trustedissuer

import (
	"fmt"

	"github.com/fiware/dsba-pdp/config"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
)

const ROLES_KEY = "roles"

var logger = logging.Log()
var envConfig config.Config = config.EnvConfig{}

type CustomerCredentialVerifier struct{}

func (CustomerCredentialVerifier) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (descision model.Decision, err model.HttpError) {

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

	if len(*roleClaim.AllowedValues) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("Claim %s does not allow any role assignment.", logging.PrettyPrintObject(roleClaim))}, err
	}

	for _, role := range credentialSubject.Roles {
		if role.Target == envConfig.ProviderId() {
			descision = isRoleAllowed(role.Names, roleClaim)
			if !descision.Decision {
				return descision, err
			}
		}
	}
	return model.Decision{Decision: true, Reason: "Role claims allowed."}, err
}

func isRoleAllowed(roleNames []string, roleClaim model.Claim) (decision model.Decision) {
	allowedRoles := []string{}
	for _, allowedValue := range *roleClaim.AllowedValues {
		if v, err := allowedValue.AsAllowedValuesStringValue(); err == nil && v != "" {
			allowedRoles = append(allowedRoles, v)
		}
		if v, err := allowedValue.AsAllowedValuesRoleValue(); err == nil && v != (model.RoleValue{}) {
			allowedRoles = append(allowedRoles, *v.Name...)
		}
	}
	for _, roleName := range roleNames {
		if !contains(allowedRoles, roleName) {
			return model.Decision{Decision: false, Reason: fmt.Sprintf("Role %s is not coverd by the roles-claim capability %s.", roleName, logging.PrettyPrintObject(roleClaim))}

		}
	}
	return model.Decision{Decision: true, Reason: "Roles allowed."}
}
