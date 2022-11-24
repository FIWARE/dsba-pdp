package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

/**
* Indicates that we have a supported ngsi-ld path.
 */
const ngsiPathIndicator string = "/ngsi-ld/v1/entities"

func (iShareDecider) Decide(token *DSBAToken, originalAddress string, requestType string, requestBody *map[string]interface{}) (decision Decision, httpErr httpError) {

	// we need to use this as request target to check request towards ourself
	requestTarget := iShareClientId
	verifiableCredential := token.VerifiableCredential
	logger.Debugf("Received VC: %s", prettyPrintObject(verifiableCredential))
	roleIssuer := verifiableCredential.Issuer
	if roleIssuer == "" {
		return Decision{false, fmt.Sprintf("The VC %s did not contain a valid iShare-role issuer.", prettyPrintObject(verifiableCredential))}, httpErr
	}

	credentialsSubject := verifiableCredential.CredentialSubject

	var authorizationRegistry *AuthorizationRegistry
	if credentialsSubject.IShareCredentialsSubject == nil || credentialsSubject.IShareCredentialsSubject.AuthorizationRegistry == nil {
		authorizationRegistry = &PDPAuthorizationRegistry
	} else {
		authorizationRegistry = credentialsSubject.IShareCredentialsSubject.AuthorizationRegistry
	}

	if len(credentialsSubject.Roles) == 0 {
		return Decision{false, fmt.Sprintf("The VC %s does not contain any roles.", prettyPrintObject(credentialsSubject))}, httpErr
	}

	requiredPolicies, httpErr := buildRequiredPolicies(originalAddress, requestType, requestBody)
	if httpErr != (httpError{}) {
		return decision, httpErr
	}

	// in case of an IShareCustomerCredential, we need to check if the role-issuer has enough rights to access the request-target, before checking the delegation, e.g. the roles
	if credentialsSubject.IShareCredentialsSubject != nil {
		decision, httpErr = checkIShareTarget(requestTarget, roleIssuer, &requiredPolicies)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			return decision, httpErr
		}
	}

	for _, role := range credentialsSubject.Roles {

		if role.Target == ProviderId {
			decision, httpErr = decideForRole(requestTarget, roleIssuer, role, authorizationRegistry, &requiredPolicies)
			if httpErr != (httpError{}) {
				return decision, httpErr
			}
			if decision.Decision {
				return decision, httpErr
			}
		}

	}
	return Decision{false, fmt.Sprintf("Was not able to find a role allowing the access to %s - %s in VC %s.", requestType, requestTarget, prettyPrintObject(verifiableCredential))}, httpErr
}

func decideForRole(requestTarget string, roleIssuer string, role Role, authorizationRegistry *AuthorizationRegistry, requiredPolicies *[]Policy) (decision Decision, httpErr httpError) {
	for _, roleName := range role.Name {
		decision, httpErr = decideForRolename(requestTarget, roleIssuer, roleName, authorizationRegistry, requiredPolicies)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			return decision, httpErr
		}
	}
	return decision, httpErr
}

func checkIShareTarget(requestTarget string, roleIssuer string, requiredPolicies *[]Policy) (decision Decision, httpErr httpError) {
	delegationEvidenceForRole, httpErr := getDelegationEvidence(requestTarget, roleIssuer, requiredPolicies, &PDPAuthorizationRegistry)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", prettyPrintObject(&PDPAuthorizationRegistry))
		return decision, httpErr
	}
	decision = checkDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", prettyPrintObject(decision))
	return decision, httpErr
}

func decideForRolename(requestTarget string, roleIssuer string, roleName string, authorizationRegistry *AuthorizationRegistry, requiredPolicies *[]Policy) (decision Decision, httpErr httpError) {

	delegationEvidenceForRole, httpErr := getDelegationEvidence(roleIssuer, roleName, requiredPolicies, authorizationRegistry)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", prettyPrintObject(authorizationRegistry))
		return decision, httpErr
	}
	decision = checkDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", prettyPrintObject(decision))
	return decision, httpErr
}

func checkDelegationEvidence(delegationEvidence *DelegationEvidence) (decision Decision) {
	if !isActive(delegationEvidence) {
		return Decision{false, fmt.Sprintf("DelegationEvidence %s is not inside a valid time range.", prettyPrintObject(*delegationEvidence))}
	}

	if !doesPermitRequest(&delegationEvidence.PolicySets) {
		return Decision{false, fmt.Sprintf("DelegationEvidence %s does not permit the request.", prettyPrintObject(*delegationEvidence))}
	}

	return Decision{true, "Request allowed."}
}

func buildRequiredPolicies(originalAddress string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {
	requestedUrl, err := url.Parse(originalAddress)

	if err != nil {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The original address is not a url %s", originalAddress), err}
	}

	if !strings.Contains(requestedUrl.Path, ngsiPathIndicator) {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The original address is not an ngsi request %s", originalAddress), err}
	}

	plainPath := strings.ReplaceAll(requestedUrl.Path, ngsiPathIndicator, "")

	// base entities request
	if plainPath == "" {
		return buildRequiredPoliciesForEntities(requestedUrl, requestType, requestBody)
	}

	// if not, it has to contain an Entity ID
	pathParts := strings.Split(plainPath, "/")
	entityId := pathParts[0]

	// only the entity id
	if len(pathParts) == 1 {
		return buildRequiredPoliciesForEntity(entityId, requestType, requestBody)
	} else
	// attributes request
	if strings.HasSuffix(plainPath, "/attrs") {
		return buildRequiredPoliciesForAttrs(entityId, requestType, requestBody)
	} else
	// request to a single attribute
	if strings.Contains(plainPath, "/attrs") {
		return buildRequiredPoliciesForSingleAttr(entityId, pathParts[len(pathParts)-1], requestType)
	}
	return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The request %s : %s is not supported by the iShareDecider.", requestType, originalAddress), nil}
}

func buildRequiredPoliciesForEntity(entityId string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {
	var resource Resource

	entityType, httpErr := getTypeFromId(entityId)
	if httpErr != (httpError{}) {
		return policies, httpErr
	}

	if requestType == "GET" || requestType == "DELETE" {
		resource = Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  []string{"*"},
		}
	} else
	// overwrites the full entity, e.g. no attribute restriction can be allowed
	if requestType == "PUT" {
		resource = Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  []string{"*"},
		}
	} else
	// on PATCH, only the attributes in the request body are touched, e.g. the can be included.
	if requestType == "PATCH" {
		resource = Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  getAttributesFromBody(requestBody),
		}
	} else {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /entities/{id}.", requestType), nil}
	}
	// empty env is again a workaround for ishare test ar...
	return []Policy{{Target: &PolicyTarget{Resource: &resource, Actions: []string{requestType}, Environment: &Environment{ServiceProviders: []string{}}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr

}

func buildRequiredPoliciesForSingleAttr(entityId string, attributeName string, requestType string) (policies []Policy, httpErr httpError) {
	if requestType != "POST" && requestType != "PATCH" && requestType != "DELETE" {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /attrs.", requestType), nil}
	}
	entityType, httpErr := getTypeFromId(entityId)

	if httpErr != (httpError{}) {
		return policies, httpErr
	}

	resource := Resource{
		Type:        entityType,
		Identifiers: []string{entityId},
		Attributes:  []string{attributeName},
	}
	return []Policy{{Target: &PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForAttrs(entityId string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {

	if requestType != "POST" && requestType != "PATCH" {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /attrs.", requestType), nil}
	}

	resource := Resource{
		Type:        (*requestBody)["type"].(string),
		Identifiers: []string{entityId},
		Attributes:  getAttributesFromBody(requestBody)}

	return []Policy{{Target: &PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForEntities(requestUrl *url.URL, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {

	var resource Resource

	if requestType == "GET" {
		entityType := requestUrl.Query().Get("type")
		identifiers := deleteEmpty(strings.Split(requestUrl.Query().Get("id"), ","))
		attributes := deleteEmpty(strings.Split(requestUrl.Query().Get("attrs"), ","))
		if entityType == "" && len(identifiers) == 0 && len(attributes) == 0 {
			return policies, httpError{http.StatusBadRequest, fmt.Sprint("GET-Requests to /entities requires at least one of type, id or attrs.", requestType), nil}
		}
		// workaround for the broken ishare ar-api
		if len(attributes) == 0 {
			attributes = append(attributes, "*")
		}
		if len(identifiers) == 0 {
			identifiers = append(identifiers, "*")
		}

		resource = Resource{
			Type:        entityType,
			Identifiers: identifiers,
			Attributes:  attributes}
	} else if requestType == "POST" {
		resource = Resource{
			Type:        (*requestBody)["type"].(string),
			Identifiers: []string{"*"},
			Attributes:  getAttributesFromBody(requestBody)}
	} else {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /entities.", requestType), nil}
	}

	return []Policy{{Target: &PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr

}

func getAttributesFromBody(requestBody *map[string]interface{}) (attributes []string) {
	for k := range *requestBody {
		if k == "type" {
			continue
		}
		attributes = append(attributes, k)
	}
	return
}

func getTypeFromId(entityId string) (entityType string, httpErr httpError) {
	idParts := strings.Split(entityId, ":")

	if len(idParts) < 4 {
		return entityType, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not a valid entity id.", entityId), nil}
	}
	return idParts[2], httpErr
}

func parseIShareToken(tokenString string) (parsedToken *IShareToken, httpErr httpError) {
	token, err := jwt.ParseWithClaims(tokenString, &IShareToken{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid_token_method")
		}

		x5cInterfaces := (*token).Header["x5c"].([]interface{})
		// the first in the chain is the client cert
		decodedClientCert, err := base64.StdEncoding.DecodeString(x5cInterfaces[0].(string))
		if err != nil {
			logger.Warnf("The client cert could not be decoded. Token: %s", tokenString)
			return nil, err
		}
		clientCert, err := x509.ParseCertificate(decodedClientCert)
		if err != nil {
			logger.Warnf("The client cert could not be parsed. Token: %s", tokenString)
			return nil, err
		}

		rootPool := x509.NewCertPool()
		intermediatePool := x509.NewCertPool()
		lastCert := len(x5cInterfaces) - 1
		for i, cert := range x5cInterfaces {
			if i == 0 {
				// skip client cert
				continue
			}
			decodedCert, err := base64.StdEncoding.DecodeString(cert.(string))
			if err != nil {
				logger.Warnf("The cert could not be decoded. Cert: %s", cert.(string))
				return nil, err
			}
			parsedCert, err := x509.ParseCertificate(decodedCert)
			if err != nil {
				logger.Warnf("The cert could not be parsed. Cert: %s", cert.(string))
				return nil, err
			}
			if i == lastCert {
				rootPool.AddCert(parsedCert)
				continue
			}
			intermediatePool.AddCert(parsedCert)
		}
		opts := x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}}
		if _, err := clientCert.Verify(opts); err != nil {
			logger.Warnf("The cert could not be verified.")
			return nil, err
		}

		logger.Debugf("Parsed certificate is: %v", clientCert)
		return clientCert.PublicKey.(*rsa.PublicKey), nil
	})

	if err != nil {
		return parsedToken, httpError{http.StatusBadGateway, fmt.Sprintf("Was not able to parse token. Error: %v", err), err}
	}
	if !token.Valid {
		return parsedToken, httpError{http.StatusBadGateway, fmt.Sprintf("Did not receive a valid token. Error: %v", err), err}
	}
	return token.Claims.(*IShareToken), httpErr

}

func isActive(delegationEvidence *DelegationEvidence) bool {

	timeNotBefore := time.Unix((*delegationEvidence).NotBefore, 0)
	timeNotOnOrAfter := time.Unix((*delegationEvidence).NotOnOrAfter, 0)
	timeNow := time.Now()

	isNotBefore := timeNow.Before(timeNotBefore)
	isNotAfter := timeNow.After(timeNotOnOrAfter)
	isNotNow := timeNow.Equal(timeNotOnOrAfter)

	if !isNotBefore && !isNotAfter && !isNotNow {
		return true
	}

	logger.Debugf("The retrieved delegation evidence %v is not active anymore. IsNotBefore: %v IsNotAfter: %v IsNotNow: %v", prettyPrintObject(*delegationEvidence), isNotBefore, isNotAfter, isNotNow)
	return false
}

func doesPermitRequest(policySets *[]PolicySet) bool {
	if policySets == nil || len(*policySets) == 0 {
		logger.Debug("No permit policy found, since the policy sets array is empty: %v", prettyPrintObject(*policySets))
		return false
	}
	for _, policySet := range *policySets {
		if !doesSetPermitRequest(&policySet) {
			logger.Debugf("PolicySet does not permit the request: %v.", prettyPrintObject(*policySets))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %v", prettyPrintObject(*policySets))
	return true
}

func doesSetPermitRequest(policySet *PolicySet) bool {
	if policySet.Policies == nil || len(policySet.Policies) == 0 {
		logger.Debug("No permit policy found, since the policies array is empty for set: %v", prettyPrintObject(*policySet))
		return false
	}
	for _, policy := range policySet.Policies {
		if !doRulesPermitRequest(&policy.Rules) {
			logger.Debugf("Policy does not permit the request: %v.", prettyPrintObject(policy))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %v", prettyPrintObject(*policySet))
	return true
}

func doRulesPermitRequest(rules *[]Rule) bool {
	if rules == nil || len(*rules) == 0 {
		logger.Debug("No permit rule found, since the rule array is empty.")
		return false

	}
	for _, rule := range *rules {
		if rule.Effect != iSharePermitEffect {
			logger.Debugf("Request denied, found a non-permit rule: %v", prettyPrintObject(rule))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %v", prettyPrintObject(*rules))
	return true

}

type iShareDecider struct{}
