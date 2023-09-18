package ishare

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/fiware/dsba-pdp/config"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
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

func (isd IShareDecider) Decide(verifiableCredential *model.DSBAVerifiableCredential, originalAddress string, requestType string, requestBody *map[string]interface{}) (decision model.Decision, httpErr model.HttpError) {

	// we need to use this as request target to check request towards ourself
	requestTarget := iShareClientId
	logger.Debugf("Received VC: %s,", logging.PrettyPrintObject(verifiableCredential))
	logger.Debugf("Creating decision for request %s - %s.", requestType, originalAddress)
	roleIssuer := isd.envConfig.ProviderId()
	if roleIssuer == "" {
		return model.Decision{Decision: false, Reason: "No valid iShare-role issuer configured."}, httpErr
	}

	credentialsSubject := verifiableCredential.CredentialSubject

	if len(credentialsSubject.Roles.Roles) == 0 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("The VC %s does not contain any roles.", logging.PrettyPrintObject(credentialsSubject))}, httpErr
	}

	requiredPolicies, httpErr := buildRequiredPolicies(originalAddress, requestType, requestBody)
	if httpErr != (model.HttpError{}) {
		return decision, httpErr
	}
	logger.Debugf("Require policies: %s", logging.PrettyPrintObject(requiredPolicies))

	for _, role := range credentialsSubject.Roles.Roles {
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

			decision, httpErr = isd.decideForRole(requestTarget, authorizationRegistry.Id, role, authorizationRegistry, &requiredPolicies)
			if httpErr != (model.HttpError{}) {
				logger.Debugf("Got error %s for role %s.", logging.PrettyPrintObject(httpErr), role)
				return decision, httpErr
			}
			if decision.Decision {
				logger.Debugf("Got success for role %s.", role)
				return decision, httpErr
			}
		}

	}
	return model.Decision{Decision: false, Reason: fmt.Sprintf("Was not able to find a role allowing the access to %s - %s in VC %s.", requestType, requestTarget, logging.PrettyPrintObject(verifiableCredential))}, httpErr
}

func (isd IShareDecider) decideForRole(requestTarget string, roleIssuer string, role model.Role, authorizationRegistry *model.AuthorizationRegistry, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {
	for _, roleName := range role.Names {
		logger.Debugf("Request decision for role %s and issuer %s.", role, roleIssuer)
		decision, httpErr = isd.decideForRolename(requestTarget, roleIssuer, roleName, authorizationRegistry, requiredPolicies)
		if httpErr != (model.HttpError{}) {
			logger.Debugf("Got error %s for %s", roleName, logging.PrettyPrintObject(httpErr))
			if httpErr.Status == 404 {
				logger.Debug("404 error, drop the error.")
				continue
			}
			return decision, httpErr
		}
		if decision.Decision {
			logger.Debugf("Got success for %s", roleName)
			return decision, httpErr
		}
	}
	return decision, httpErr
}

func (isd IShareDecider) checkIShareTarget(requestTarget string, roleIssuer string, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {
	logger.Debugf("Check target %s with role %s. Policies: %s", requestTarget, roleIssuer, logging.PrettyPrintObject(requiredPolicies))
	delegationEvidenceForRole, httpErr := isd.iShareAuthorizationRegistry.GetDelegationEvidence(requestTarget, roleIssuer, requiredPolicies, isd.iShareAuthorizationRegistry.GetPDPRegistry())
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", logging.PrettyPrintObject(isd.iShareAuthorizationRegistry.GetPDPRegistry()))
		return decision, httpErr
	}
	decision = CheckDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", logging.PrettyPrintObject(decision))
	return decision, httpErr
}

func (isd IShareDecider) decideForRolename(requestTarget string, roleIssuer string, roleName string, authorizationRegistry *model.AuthorizationRegistry, requiredPolicies *[]model.Policy) (decision model.Decision, httpErr model.HttpError) {

	delegationEvidenceForRole, httpErr := isd.iShareAuthorizationRegistry.GetDelegationEvidence(roleIssuer, roleName, requiredPolicies, authorizationRegistry)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get the delegation evidence from the role ar: %v", logging.PrettyPrintObject(authorizationRegistry))
		return decision, httpErr
	}
	decision = CheckDelegationEvidence(delegationEvidenceForRole)
	logger.Debugf("Decision for the role is: %s", logging.PrettyPrintObject(decision))
	return decision, httpErr
}

func CheckDelegationEvidence(delegationEvidence *model.DelegationEvidence) (decision model.Decision) {
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
		logger.Debugf("Received a non ngsi-ld path, will build http policies.")
		return buildHttpPolicy(requestedUrl.Path, requestType)
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

// in case of non-ngsi requests, we build http-path requests.
func buildHttpPolicy(path string, requestType string) (policies []model.Policy, httpErr model.HttpError) {
	resourcePaths := buildResourcePaths(path)
	for _, path := range resourcePaths {
		policies = append(policies, model.Policy{
			Target: &model.PolicyTarget{
				Resource: &model.Resource{
					Type:        "PATH",
					Identifiers: []string{path},
					Attributes:  []string{},
				},
				Actions: []string{requestType}},
			Rules: []model.Rule{{Effect: "Permit"}}})

	}
	return policies, httpErr
}

// create the resource paths. At least one of them needs to exist to be allowed
func buildResourcePaths(path string) (paths []string) {
	pathParts := strings.Split(path, "/")

	for i, part := range pathParts {
		if part == "" {
			continue
		}

		starPath := "/"
		currentPart := "/"
		for ni, subPart := range pathParts {
			if subPart != "" && ni < i {
				starPath = starPath + subPart + "/"
				currentPart = currentPart + subPart + "/"
			}
		}
		paths = append(paths, starPath+"*")
		paths = append(paths, currentPart+part)

	}
	return paths
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
	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr

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

	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr
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

	return []model.Policy{{Target: &model.PolicyTarget{Resource: &resource, Actions: []string{requestType}}, Rules: []model.Rule{{Effect: "Permit"}}}}, httpErr

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
