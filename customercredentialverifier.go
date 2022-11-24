package main

import (
	"fmt"
)

type CustomerCredentialVerifier struct{}

func (CustomerCredentialVerifier) Verify(claims *[]Claim, credentialSubject *CredentialSubject) (descision Decision, err httpError) {

	// check that no addtional information is included

	if credentialSubject.IShareCredentialsSubject != nil {
		return Decision{false, fmt.Sprintf("The credential %s includes forbidden claims.", prettyPrintObject(*credentialSubject))}, err
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
		if role.Target == ProviderId {
			descision = isRoleAllowed(role.Name, roleClaim)
			if !descision.Decision {
				return descision, err
			}
		}
	}
	return Decision{true, "Role claims allowed."}, err
}

func isRoleAllowed(roleNames []string, roleClaim Claim) (decision Decision) {
	for _, roleName := range roleNames {
		if !contains(roleClaim.AllowedValues, roleName) {
			return Decision{false, fmt.Sprintf("Role %s is not coverd by the roles-claim capability %s.", roleName, prettyPrintObject(roleClaim))}

		}
	}
	return Decision{true, "Roles allowed."}
}
