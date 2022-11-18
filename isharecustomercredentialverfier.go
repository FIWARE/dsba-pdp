package main

type IShareCustomerCredentialVerifier struct{}

func (IShareCustomerCredentialVerifier) Verify(claims *[]Claim, credentialSubject *CredentialSubject, issuerId string) (decision Decision, err httpError) {

	// TODO: get policies for the referenced roles from ar of issuer
	// then get policies coverd by the claims and match both.

	authorizationRegistry := credentialSubject.AuthorizationRegistry

	rolePolicies := []Policy{}
	for _, role := range credentialSubject.Roles {
		delegationEvidenceForRole, httpErr := getDelegationEvidence(issuerId, role.Name, nil, &authorizationRegistry)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}
		for _, ps := range delegationEvidenceForRole.PolicySets {
			for _, p := range ps.Policies {
				rolePolicies = append(rolePolicies, p)
			}
		}
	}

	delegationEvidence, httpErr := getDelegationEvidence(iShareClientId, issuerId, &rolePolicies, &PDPAuthorizationRegistry)
	if httpErr != (httpError{}) {
		return decision, httpErr
	}

	decision = checkDelegationEvidence(delegationEvidence)

	if !decision.Decision {
		//logger.Debugf("Issuing roles for  %s to the request target %s is not permitted by delegation evidence %s.", roleIssuer, requestTarget, prettyPrintObject(delegationEvidenceForRequestTarget))
		return decision, httpErr
	}
	return decision, httpErr
}
