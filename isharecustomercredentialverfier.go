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

	authorizationRegistry := credentialSubject.AuthorizationRegistry
	// check allowed ar's
	if authorizationRegistry.Id == "" {
		logger.Debugf("No dedicated ar defined, allow it.")
		return Decision{true, "VC does not define its own AR, all checks are fine."}, httpErr

	}

	arClaim := Claim{}

	for _, claim := range *claims {
		if claim.Name == "authorizationRegistry" {
			arClaim = claim
			break
		}
	}
	if arClaim.Name == "" {
		return Decision{true, "No restrictions for the ar exist."}, err
	}

	if len(arClaim.AllowedValues) == 0 {
		return Decision{false, fmt.Sprintf("Claim %s does not allow any definition of an ar.", prettyPrintObject(arClaim))}, err
	}

	if contains(arClaim.AllowedValues, credentialSubject.AuthorizationRegistry.Id) {
		return Decision{true, "Defined AR is allowed."}, httpErr
	}

	return Decision{false, fmt.Sprintf("Defined AR 1%s is not covered by the ar-claim %s", credentialSubject.AuthorizationRegistry.Id, prettyPrintObject(arClaim))}, httpErr
}
