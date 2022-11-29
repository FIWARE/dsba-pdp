package decision

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
	"github.com/wistefan/dsba-pdp/config"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

/**
* Indicates that we have a supported ngsi-ld path.
 */
const ngsiPathIndicator string = "/ngsi-ld/v1/entities"

func NewIShareDecider(ar AuthorizationRegistry, config config.Config) *IShareDecider {
	iShareDecider := new(IShareDecider)
	iShareDecider.iShareAuthorizationRegistry = ar
	iShareDecider.envConfig = config
	return iShareDecider
}

func (isd IShareDecider) Decide(token *model.DSBAToken, originalAddress string, requestType string, requestBody *map[string]interface{}) (decision model.Decision, httpErr model.HttpError) {

	// we need to use this as request target to check request towards ourself
	requestTarget := iShareClientId
	verifiableCredential := token.VerifiableCredential
	logger.Debugf("Received VC: %s,", logging.PrettyPrintObject(verifiableCredential))
	logger.Debugf("Creating decision for request %s - %s.", requestType, originalAddress)
	roleIssuer := verifiableCredential.Issuer
	if roleIssuer == "" {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("The VC %s did not contain a valid iShare-role issuer.", logging.PrettyPrintObject(verifiableCredential))}, httpErr
	}

	credentialsSubject := verifiableCredential.CredentialSubject

	if len(credentialsSubject.Roles) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("The VC %s does not contain any roles.", logging.PrettyPrintObject(credentialsSubject))}, httpErr
	}

	requiredPolicies, httpErr := buildRequiredPolicies(originalAddress, requestType, requestBody)
	if httpErr != (model.HttpError{}) {
		return decision, httpErr
	}

	// in case of an IShareCustomerCredential, we need to check if the role-issuer has enough rights to access the request-target, before checking the delegation, e.g. the roles
	if credentialsSubject.IShareCredentialsSubject != nil {

		decision, httpErr = isd.checkIShareTarget(requestTarget, roleIssuer, &requiredPolicies)
		if httpErr != (model.HttpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			return decision, httpErr
		}
	}

	for _, role := range credentialsSubject.Roles {

		if role.Target == isd.envConfig.ProviderId() {
			var authorizationRegistry *model.AuthorizationRegistry
			if role.Provider == "" {
				authorizationRegistry = isd.iShareAuthorizationRegistry.GetPDPRegistry()
			} else if credentialsSubject.AuthorizationRegistries != nil {
				if ar, ok := (*credentialsSubject.AuthorizationRegistries)[role.Provider]; ok {
					authorizationRegistry = &ar
				} else {
					return decision, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("No authorization registry configured for the role provider %s.", role.Provider)}
				}
			} else {
				return decision, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("No authorization registry configured for the role provider %s.", role.Provider)}
			}

			decision, httpErr = isd.decideForRole(requestTarget, roleIssuer, role, authorizationRegistry, &requiredPolicies)
			if httpErr != (model.HttpError{}) {
				return decision, httpErr
			}
			if decision.Decision {
				return decision, httpErr
			}
		}

	}
	return model.Decision{Decision: false, Reason: fmt.Sprintf("Was not able to find a role allowing the access to %s - %s in VC %s.", requestType, requestTarget, logging.PrettyPrintObject(verifiableCredential))}, httpErr
}

func (isd IShareDecider) decideForRole(requestTarget string, roleIssuer string, role model.Role, authorizationRegistry *model.AuthorizationRegistry, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {
	for _, roleName := range role.Name {
		decision, httpErr = isd.decideForRolename(requestTarget, roleIssuer, roleName, authorizationRegistry, requiredPolicies)
		if httpErr != (model.HttpError{}) {
			return decision, httpErr
		}
		if decision.Decision {
			return decision, httpErr
		}
	}
	return decision, httpErr
}

func (isd IShareDecider) checkIShareTarget(requestTarget string, roleIssuer string, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {
	delegationEvidenceForRole, httpErr := isd.iShareAuthorizationRegistry.GetDelegationEvidence(requestTarget, roleIssuer, requiredPolicies, isd.iShareAuthorizationRegistry.GetPDPRegistry())
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", logging.PrettyPrintObject(isd.iShareAuthorizationRegistry.GetPDPRegistry()))
		return decision, httpErr
	}
	decision = checkDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", logging.PrettyPrintObject(decision))
	return decision, httpErr
}

func (isd IShareDecider) decideForRolename(requestTarget string, roleIssuer string, roleName string, authorizationRegistry *model.AuthorizationRegistry, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {

	delegationEvidenceForRole, httpErr := isd.iShareAuthorizationRegistry.GetDelegationEvidence(roleIssuer, roleName, requiredPolicies, authorizationRegistry)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", logging.PrettyPrintObject(authorizationRegistry))
		return decision, httpErr
	}
	decision = checkDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", logging.PrettyPrintObject(decision))
	return decision, httpErr
}

func checkDelegationEvidence(delegationEvidence *model.DelegationEvidence) (decision model.Decision) {
	if !isActive(delegationEvidence) {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("DelegationEvidence %s is not inside a valid time range.", logging.PrettyPrintObject(*delegationEvidence))}
	}

	if !doesPermitRequest(&delegationEvidence.PolicySets) {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("DelegationEvidence %s does not permit the request.", logging.PrettyPrintObject(*delegationEvidence))}
	}

	return model.Decision{Decision: true, Reason: "Request allowed."}
}

func buildRequiredPolicies(originalAddress string, requestType string, requestBody *map[string]interface{}) (policies []model.Policy, httpErr model.HttpError) {
	requestedUrl, err := url.Parse(originalAddress)

	if err != nil {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("The original address is not a url %s", originalAddress), RootError: err}
	}

	if !strings.Contains(requestedUrl.Path, ngsiPathIndicator) {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("The original address is not an ngsi request %s", originalAddress), RootError: err}
	}

	plainPath := strings.ReplaceAll(requestedUrl.Path, ngsiPathIndicator, "")

	// base entities request
	if plainPath == "" {
		return buildRequiredPoliciesForEntities(requestedUrl, requestType, requestBody)
	}

	// if not, it has to contain an Entity ID
	pathParts := removeEmptyStrings(strings.Split(plainPath, "/"))
	entityId := pathParts[0]

	logger.Debugf("The splited path from %s is %v.", originalAddress, pathParts)
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
	return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("The request %s : %s is not supported by the IShareDecider.", requestType, originalAddress), RootError: nil}
}

func buildRequiredPoliciesForEntity(entityId string, requestType string, requestBody *map[string]interface{}) (policies []model.Policy, httpErr model.HttpError) {
	var resource model.Resource

	entityType, httpErr := getTypeFromId(entityId)
	if httpErr != (model.HttpError{}) {
		return policies, httpErr
	}

	if requestType == "GET" || requestType == "DELETE" {
		resource = model.Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  []string{"*"},
		}
	} else
	// overwrites the full entity, e.g. no attribute restriction can be allowed
	if requestType == "PUT" {
		resource = model.Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  []string{"*"},
		}
	} else
	// on PATCH, only the attributes in the request body are touched, e.g. the can be included.
	if requestType == "PATCH" {
		resource = model.Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
			Attributes:  getAttributesFromBody(requestBody),
		}
	} else {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("%s is not supported on /entities/{id}.", requestType), RootError: nil}
	}
	// empty env is again a workaround for ishare test ar...
	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}, Environment: &model.Environment{ServiceProviders: []string{}}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr

}

func buildRequiredPoliciesForSingleAttr(entityId string, attributeName string, requestType string) (policies []model.Policy, httpErr model.HttpError) {
	if requestType != "POST" && requestType != "PATCH" && requestType != "DELETE" {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("%s is not supported on /attrs.", requestType), RootError: nil}
	}
	entityType, httpErr := getTypeFromId(entityId)

	if httpErr != (model.HttpError{}) {
		return policies, httpErr
	}

	resource := model.Resource{
		Type:        entityType,
		Identifiers: []string{entityId},
		Attributes:  []string{attributeName},
	}
	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForAttrs(entityId string, requestType string, requestBody *map[string]interface{}) (policies []model.Policy, httpErr model.HttpError) {

	if requestType != "POST" && requestType != "PATCH" {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("%s is not supported on /attrs.", requestType), RootError: nil}
	}

	resource := model.Resource{
		Type:        (*requestBody)["type"].(string),
		Identifiers: []string{entityId},
		Attributes:  getAttributesFromBody(requestBody)}

	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}, Environment: &model.Environment{ServiceProviders: []string{}}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForEntities(requestUrl *url.URL, requestType string, requestBody *map[string]interface{}) (policies []model.Policy, httpErr model.HttpError) {

	var resource model.Resource

	if requestType == "GET" {
		entityType := requestUrl.Query().Get("type")
		identifiers := deleteEmpty(strings.Split(requestUrl.Query().Get("id"), ","))
		attributes := deleteEmpty(strings.Split(requestUrl.Query().Get("attrs"), ","))
		if entityType == "" && len(identifiers) == 0 && len(attributes) == 0 {
			return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprint("GET-Requests to /entities requires at least one of type, id or attrs.", requestType), RootError: nil}
		}
		// workaround for the broken ishare ar-api
		if len(attributes) == 0 {
			attributes = append(attributes, "*")
		}
		if len(identifiers) == 0 {
			identifiers = append(identifiers, "*")
		}

		resource = model.Resource{
			Type:        entityType,
			Identifiers: identifiers,
			Attributes:  attributes}
	} else if requestType == "POST" {
		resource = model.Resource{
			Type:        (*requestBody)["type"].(string),
			Identifiers: []string{"*"},
			Attributes:  getAttributesFromBody(requestBody)}
	} else {
		return policies, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("%s is not supported on /entities.", requestType), RootError: nil}
	}

	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}, Environment: &model.Environment{ServiceProviders: []string{}}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr

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

func getTypeFromId(entityId string) (entityType string, httpErr model.HttpError) {
	idParts := strings.Split(entityId, ":")

	if len(idParts) < 4 {
		return entityType, model.HttpError{Status: http.StatusBadRequest, Message: fmt.Sprintf("%s is not a valid entity id.", entityId), RootError: nil}
	}
	return idParts[2], httpErr
}

func parseIShareToken(tokenString string) (parsedToken *model.IShareToken, httpErr model.HttpError) {
	token, err := jwt.ParseWithClaims(tokenString, &model.IShareToken{}, func(token *jwt.Token) (interface{}, error) {
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
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Was not able to parse token. Error: %v", err), RootError: err}
	}
	if !token.Valid {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive a valid token. Error: %v", err), RootError: err}
	}
	return token.Claims.(*model.IShareToken), httpErr

}

func isActive(delegationEvidence *model.DelegationEvidence) bool {

	timeNotBefore := time.Unix((*delegationEvidence).NotBefore, 0)
	timeNotOnOrAfter := time.Unix((*delegationEvidence).NotOnOrAfter, 0)
	timeNow := time.Now()

	isNotBefore := timeNow.Before(timeNotBefore)
	isNotAfter := timeNow.After(timeNotOnOrAfter)
	isNotNow := timeNow.Equal(timeNotOnOrAfter)

	if !isNotBefore && !isNotAfter && !isNotNow {
		return true
	}

	logger.Debugf("The retrieved delegation evidence %s is not active anymore. IsNotBefore: %v IsNotAfter: %v IsNotNow: %v", logging.PrettyPrintObject(*delegationEvidence), isNotBefore, isNotAfter, isNotNow)
	return false
}

func doesPermitRequest(policySets *[]model.PolicySet) bool {
	if policySets == nil || len(*policySets) == 0 {
		logger.Debugf("No permit policy found, since the policy sets array is empty: %s", logging.PrettyPrintObject(*policySets))
		return false
	}
	for _, policySet := range *policySets {
		if !doesSetPermitRequest(&policySet) {
			logger.Debugf("PolicySet does not permit the request: %s.", logging.PrettyPrintObject(*policySets))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %s", logging.PrettyPrintObject(*policySets))
	return true
}

func doesSetPermitRequest(policySet *model.PolicySet) bool {
	if policySet.Policies == nil || len(policySet.Policies) == 0 {
		logger.Debugf("No permit policy found, since the policies array is empty for set: %s", logging.PrettyPrintObject(*policySet))
		return false
	}
	for _, policy := range policySet.Policies {
		if !doRulesPermitRequest(&policy.Rules) {
			logger.Debugf("Policy does not permit the request: %s.", logging.PrettyPrintObject(policy))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %s", logging.PrettyPrintObject(*policySet))
	return true
}

func doRulesPermitRequest(rules *[]model.Rule) bool {
	if rules == nil || len(*rules) == 0 {
		logger.Debug("No permit rule found, since the rule array is empty.")
		return false

	}
	for _, rule := range *rules {
		if rule.Effect != model.ISharePermitEffect {
			logger.Debugf("Request denied, found a non-permit rule: %s", logging.PrettyPrintObject(rule))
			return false
		}
	}
	logger.Debugf("At least one permit was found in %s", logging.PrettyPrintObject(*rules))
	return true

}

func removeEmptyStrings(stringArray []string) []string {
	cleanedString := []string{}
	for _, s := range stringArray {
		if s != "" {
			cleanedString = append(cleanedString, s)
		}
	}
	return cleanedString
}

type IShareDecider struct {
	iShareAuthorizationRegistry AuthorizationRegistry
	envConfig                   config.Config
}
