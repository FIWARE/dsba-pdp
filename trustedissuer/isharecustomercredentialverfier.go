package trustedissuer

import (
	"fmt"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

const AR_KEY = "authorizationRegistry"

type IShareCustomerCredentialVerifier struct{}

func (IShareCustomerCredentialVerifier) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (decision model.Decision, httpErr model.HttpError) {

	arClaim := model.Claim{}
	roleClaim := model.Claim{}

	for _, claim := range *claims {
		if claim.Name == AR_KEY {
			arClaim = claim
		}
		if claim.Name == ROLES_KEY {
			roleClaim = claim
		}
	}

	if credentialSubject.IShareCredentialsSubject != nil {
		// ar checks are only required when an IShareCredentialsSubject is provided
		decision, httpErr = checkAuthorizationRegistries(arClaim, (*credentialSubject).AuthorizationRegistries)

		if httpErr != (model.HttpError{}) || !decision.Decision {
			logger.Debugf("AR check result is %t, message: %s, error: %v", decision.Decision, decision.Reason, httpErr)
			return decision, httpErr
		}
		logger.Debugf("AR allowed, message: %s.", decision.Reason)
	}

	decision, httpErr = checkRoles(roleClaim, credentialSubject.Roles)
	if httpErr != (model.HttpError{}) || !decision.Decision {
		logger.Debugf("Role provider check result is %t, message: %s, error: %v", decision.Decision, decision.Reason, httpErr)
		return decision, httpErr
	}

	logger.Debugf("Role provider allowed, message: %s.", decision.Reason)
	return model.Decision{Decision: true, Reason: "Subject is allowed by the iShare verifier."}, httpErr
}

func checkRoles(roleClaim model.Claim, roles []model.Role) (decision model.Decision, httpErr model.HttpError) {
	if roleClaim.Name == "" {
		return model.Decision{Decision: true, Reason: "No restrictions for the roles  exist."}, httpErr
	}

	if len(roleClaim.AllowedValues) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("Claim %s does not allow any definition of roles.", logging.PrettyPrintObject(roleClaim))}, httpErr
	}

	generalAllowedRoles := []string{}
	allowedByProvider := map[string]*[]string{}

	for _, allowedRole := range roleClaim.AllowedValues {
		if allowedRole.String != "" {
			generalAllowedRoles = append(generalAllowedRoles, allowedRole.String)
		}
		if allowedRole.RoleValue != (model.RoleValue{}) {
			allowedRoles, ok := allowedByProvider[allowedRole.RoleValue.ProviderId]
			if ok {
				*allowedRoles = append(*allowedRoles, *allowedRole.RoleValue.Name...)
			} else {
				if allowedRole.RoleValue.Name != nil {
					allowedRoles = allowedRole.RoleValue.Name
				}
			}
			allowedByProvider[allowedRole.RoleValue.ProviderId] = allowedRoles
		}
	}

	for _, role := range roles {

		decision, httpErr = checkGeneralAllowance(generalAllowedRoles, role)
		if httpErr != (model.HttpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			logger.Debugf("Role %s allowed by the general list.", logging.PrettyPrintObject(role))
			return decision, httpErr
		}

		if role.Provider != "" {
			decision, httpErr = checkAllowedByProvider(allowedByProvider, role.Provider, role.Name)
		}

		if httpErr != (model.HttpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			logger.Debugf("Role %s allowed for the provider list.", logging.PrettyPrintObject(role))
			return decision, httpErr
		}
	}
	return model.Decision{Decision: false, Reason: fmt.Sprintf("Defined role-providers %s not covered by the role-provider claim %s.", logging.PrettyPrintObject(roles), logging.PrettyPrintObject(roleClaim))}, httpErr

}

func checkAllowedByProvider(allowedByProvider map[string]*[]string, providerId string, roleNames []string) (decision model.Decision, httpErr model.HttpError) {
	allowedRoles, ok := allowedByProvider[providerId]
	if !ok {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("No entry for provider %s in %v found.", providerId, allowedByProvider)}, httpErr
	}
	if allowedRoles == nil {
		return model.Decision{Decision: true, Reason: fmt.Sprintf("No role restrictions for provider %s exist.", providerId)}, httpErr
	}
	if containsAll(*allowedRoles, roleNames) {
		return model.Decision{Decision: true, Reason: fmt.Sprintf("Role %s allowed for provider %s.", roleNames, providerId)}, httpErr
	}
	return model.Decision{Decision: false, Reason: fmt.Sprintf("Role %s not allowed for provider %s.", roleNames, providerId)}, httpErr
}

func checkGeneralAllowance(allowedRoles []string, role model.Role) (decision model.Decision, httpErr model.HttpError) {
	if containsAll(allowedRoles, role.Name) {
		return model.Decision{Decision: true, Reason: "Role is allowed."}, httpErr
	}
	return model.Decision{Decision: false, Reason: fmt.Sprintf("Role %s is not generally allowed by %v.", logging.PrettyPrintObject(role), allowedRoles)}, httpErr
}

func checkAuthorizationRegistries(arClaim model.Claim, authorizationRegistries *map[string]model.AuthorizationRegistry) (decision model.Decision, httpErr model.HttpError) {

	// check allowed ar's
	if authorizationRegistries == nil {
		logger.Debugf("No dedicated ar defined, allow it.")
		return model.Decision{Decision: true, Reason: "VC does not define its own AR, all checks are fine."}, httpErr

	}

	if arClaim.Name == "" {
		return model.Decision{Decision: true, Reason: "No restrictions for the ar exist."}, httpErr
	}

	if len(arClaim.AllowedValues) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("Claim %s does not allow any definition of an ar.", logging.PrettyPrintObject(arClaim))}, httpErr
	}

	allowedRegistries := []string{}
	for _, ar := range arClaim.AllowedValues {
		allowedRegistries = append(allowedRegistries, ar.String)
	}

	for registry := range *authorizationRegistries {
		if !contains(allowedRegistries, registry) {
			return model.Decision{Decision: false, Reason: fmt.Sprintf("Defined AR %s not covered by the ar-claim %s", registry, logging.PrettyPrintObject(arClaim))}, httpErr
		}
	}

	return model.Decision{Decision: true, Reason: "Defined ARs allowed."}, httpErr
}
