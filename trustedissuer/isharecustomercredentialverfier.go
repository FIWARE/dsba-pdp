package trustedissuer

import (
	"fmt"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

type IShareCustomerCredentialVerifier struct{}

func (IShareCustomerCredentialVerifier) Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (decision model.Decision, err model.HttpError) {

	// check roles, no difference to the CustomerCredentialVerifier
	decision, httpErr := CheckRoles(claims, credentialSubject)

	if httpErr != (model.HttpError{}) || !decision.Decision {
		logger.Debugf("Denied by the CustomerCredentialVerifier")
		return decision, httpErr
	}

	arClaim := model.Claim{}
	roleProviderClaim := model.Claim{}

	for _, claim := range *claims {
		if claim.Name == "authorizationRegistry" {
			arClaim = claim
		}
		if claim.Name == "roles.provider" {
			roleProviderClaim = claim
		}
	}

	decision, httpErr = checkAuthorizationRegistries(arClaim, credentialSubject.AuthorizationRegistries)

	if httpErr != (model.HttpError{}) || !decision.Decision {
		return decision, httpErr
	}

	decision, httpErr = checkRoleProviders(roleProviderClaim, credentialSubject.Roles)
	if httpErr != (model.HttpError{}) || !decision.Decision {
		return decision, httpErr
	}

	return model.Decision{true, "Subject is allowed by the iShare verifier."}, httpErr
}

func checkRoleProviders(roleProviderClaim model.Claim, roles []model.Role) (decision model.Decision, httpErr model.HttpError) {
	if roleProviderClaim.Name == "" {
		return model.Decision{true, "No restrictions for the role provider exist."}, httpErr
	}

	if len(roleProviderClaim.AllowedValues) == 0 {
		return model.Decision{false, fmt.Sprintf("Claim %s does not allow any definition of roleProviders.", logging.PrettyPrintObject(roleProviderClaim))}, httpErr
	}

	for _, role := range roles {
		if role.Provider == "" {
			return model.Decision{true, "No provider defined by the role, use the default."}, httpErr
		}
		if contains(roleProviderClaim.AllowedValues, role.Provider) {
			return model.Decision{true, "Defined provider is allowed."}, httpErr
		}
	}
	return model.Decision{false, fmt.Sprintf("Defined role-providers %s not covered by the role-provider claim %s.", logging.PrettyPrintObject(roles), logging.PrettyPrintObject(roleProviderClaim))}, httpErr

}

func checkAuthorizationRegistries(arClaim model.Claim, authorizationRegistries *map[string]model.AuthorizationRegistry) (decision model.Decision, httpErr model.HttpError) {

	// check allowed ar's
	if authorizationRegistries == nil {
		logger.Debugf("No dedicated ar defined, allow it.")
		return model.Decision{true, "VC does not define its own AR, all checks are fine."}, httpErr

	}

	if arClaim.Name == "" {
		return model.Decision{true, "No restrictions for the ar exist."}, httpErr
	}

	if len(arClaim.AllowedValues) == 0 {
		return model.Decision{false, fmt.Sprintf("Claim %s does not allow any definition of an ar.", logging.PrettyPrintObject(arClaim))}, httpErr
	}

	for registry := range *authorizationRegistries {
		if contains(arClaim.AllowedValues, registry) {
			return model.Decision{true, "Defined AR is allowed."}, httpErr
		}
	}

	return model.Decision{false, fmt.Sprintf("Defined ARs %s not covered by the ar-claim %s", logging.PrettyPrintObject(*authorizationRegistries), logging.PrettyPrintObject(arClaim))}, httpErr
}
