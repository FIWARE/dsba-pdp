package main

import "fmt"

type IShareCustomerCredentialVerifier struct{}

func (IShareCustomerCredentialVerifier) Verify(claims *[]Claim, credentialSubject *CredentialSubject, issuerId string) (decision Decision, err httpError) {

	// check roles, no difference to the CustomerCredentialVerifier
	decision, httpErr := CheckRoles(claims, credentialSubject)

	if httpErr != (httpError{}) || !decision.Decision {
		logger.Debugf("Denied by the CustomerCredentialVerifier")
		return decision, httpErr
	}

	arClaim := Claim{}
	roleProviderClaim := Claim{}

	for _, claim := range *claims {
		if claim.Name == "authorizationRegistry" {
			arClaim = claim
		}
		if claim.Name == "roles.provider" {
			roleProviderClaim = claim
		}
	}

	decision, httpErr = checkAuthorizationRegistries(arClaim, credentialSubject.AuthorizationRegistries)

	if httpErr != (httpError{}) || !decision.Decision {
		return decision, httpErr
	}

	decision, httpErr = checkRoleProviders(roleProviderClaim, credentialSubject.Roles)
	if httpErr != (httpError{}) || !decision.Decision {
		return decision, httpErr
	}

	return Decision{true, "Subject is allowed by the iShare verifier."}, httpErr
}

func checkRoleProviders(roleProviderClaim Claim, roles []Role) (decision Decision, httpErr httpError) {
	if roleProviderClaim.Name == "" {
		return Decision{true, "No restrictions for the role provider exist."}, httpErr
	}

	if len(roleProviderClaim.AllowedValues) == 0 {
		return Decision{false, fmt.Sprintf("Claim %s does not allow any definition of roleProviders.", prettyPrintObject(roleProviderClaim))}, httpErr
	}

	for _, role := range roles {
		if role.Provider == "" {
			return Decision{true, "No provider defined by the role, use the default."}, httpErr
		}
		if contains(roleProviderClaim.AllowedValues, role.Provider) {
			return Decision{true, "Defined provider is allowed."}, httpErr
		}
	}
	return Decision{false, fmt.Sprintf("Defined role-providers %s not covered by the role-provider claim %s.", prettyPrintObject(roles), prettyPrintObject(roleProviderClaim))}, httpErr

}

func checkAuthorizationRegistries(arClaim Claim, authorizationRegistries *map[string]AuthorizationRegistry) (decision Decision, httpErr httpError) {

	// check allowed ar's
	if authorizationRegistries == nil {
		logger.Debugf("No dedicated ar defined, allow it.")
		return Decision{true, "VC does not define its own AR, all checks are fine."}, httpErr

	}

	if arClaim.Name == "" {
		return Decision{true, "No restrictions for the ar exist."}, httpErr
	}

	if len(arClaim.AllowedValues) == 0 {
		return Decision{false, fmt.Sprintf("Claim %s does not allow any definition of an ar.", prettyPrintObject(arClaim))}, httpErr
	}

	for registry := range *authorizationRegistries {
		if contains(arClaim.AllowedValues, registry) {
			return Decision{true, "Defined AR is allowed."}, httpErr
		}
	}

	return Decision{false, fmt.Sprintf("Defined ARs %s not covered by the ar-claim %s", prettyPrintObject(*authorizationRegistries), prettyPrintObject(arClaim))}, httpErr
}
