package main

import (
	"fmt"
)

type CustomerCredentialVerifier struct{}

func (CustomerCredentialVerifier) Verify(claims *[]Claim, credentialSubject *CredentialSubject) (descision Decision, err httpError) {

	// check that no addtional information is included

	if credentialSubject.IShareCredentialsSubject != nil {
		return Decision{false, fmt.Sprintf("The credential %s includes forbidden claims.", prettyPrintObject(*credentialSubject))}, er
	}
	return CheckRoles(claims, credentialSubject)
}

func CheckRoles(claims *[]Claim, credentialSubject *CredentialSubject) (descision Decision, err httpError) {
	roleClaim := Claim{}
	for _, claim := range *claims {
		if claim.Name == "roles" {
			roleClaim = claim
			break
		}
	}
	if roleClaim.Name == "" {
		return Decision{true, "No restrictions for roles exist."}, err
	}

	if len(roleClaim.AllowedValues) == 0 {
		return Decision{false, fmt.Sprintf("Claim %s does not allow any role assignment.", prettyPrintObject(roleClaim))}, err
	}

	for _, role := range credentialSubject.Roles {
		if !contains(roleClaim.AllowedValues, role.Name) {
			return Decision{false, fmt.Sprintf("Role %s is not coverd by the roles-claim capability %s.", role, prettyPrintObject(roleClaim))}, err
		}
	}
	return Decision{true, "Role claims allowed."}, err
}
