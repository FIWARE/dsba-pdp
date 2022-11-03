package main

import (
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v4"
)

var ngsiPathIndicator string = "ngsi-ld/v1/entities"

func (iShareDecider) Decide(token string, originalAddress string, requestType string, requestBody *map[string]interface{}) (decision Decision, httpErr httpError) {

	// verification should already have happend, pdp only decides based on the presented information
	parsedToken, _, err := jwt.NewParser().ParseUnverified(token, &IShareToken{})
	if err != nil {
		return decision, httpError{http.StatusUnauthorized, "No proper jwt was provided", err}
	}

	claims := parsedToken.Claims.(*IShareToken)
	issuer := claims.Issuer
	subject := claims.Subject

	delegationEvidence := &claims.DelegationEvidence

	// issuer is requiered, so we take it as an indicator, since we cannot compare in-depth(due to the embedded slice)
	if delegationEvidence.PolicyIssuer == "" {
		requiredPolicies, httpErr := buildRequiredPolicies(originalAddress, requestType, requestBody)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}

		delegationEvidence, httpErr = getDelegationEvidence(issuer, subject, requiredPolicies)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}
	}

	if !isActive(delegationEvidence) {
		return Decision{false, fmt.Sprintf("DelegationEvidence for issuer %s and subject %s is not inside a valid time range.", issuer, subject)}, httpErr
	}

	return decision, httpErr
}

func buildRequiredPolicies(originalAddress string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {
	requestedUrl, err := url.Parse(originalAddress)

	if err != nil {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The original address is not a url %s", originalAddress), err}
	}

	if !strings.Contains(requestedUrl.Path, ngsiPathIndicator) {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The original address is not an ngsi request %s", originalAddress), err}
	}

	plainPath := strings.ReplaceAll(ngsiPathIndicator, requestedUrl.Path, "")

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
	return policies, httpError{http.StatusBadRequest, fmt.Sprintf("The request %s:%s is not supported by the iShareDecider.", requestType, originalAddress), nil}
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
		}
	} else
	// overwrites the full entity, e.g. no attribute restriction can be allowed
	if requestType == "PUT" {
		resource = Resource{
			Type:        entityType,
			Identifiers: []string{entityId},
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
	return []Policy{Policy{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}}, Rules: []Rule{Rule{Effect: "Permit"}}}}, httpErr

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
	return []Policy{Policy{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}}, Rules: []Rule{Rule{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForAttrs(entityId string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {

	if requestType != "POST" && requestType != "PATCH" {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /attrs.", requestType), nil}
	}

	resource := Resource{
		Type:        (*requestBody)["type"].(string),
		Identifiers: []string{entityId},
		Attributes:  getAttributesFromBody(requestBody)}

	return []Policy{Policy{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}}, Rules: []Rule{Rule{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForEntities(requestUrl *url.URL, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {

	var resource Resource

	if requestType == "GET" {
		resource = Resource{
			Type:        requestUrl.Query().Get("type"),
			Identifiers: strings.Split(requestUrl.Query().Get("id"), ","),
			Attributes:  strings.Split(requestUrl.Query().Get("attrs"), ",")}
	} else if requestType == "POST" {
		resource = Resource{
			Type:       (*requestBody)["type"].(string),
			Attributes: getAttributesFromBody(requestBody)}
	} else {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /entities.", requestType), nil}
	}
	return []Policy{Policy{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}}, Rules: []Rule{Rule{Effect: "Permit"}}}}, httpErr

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

func isActive(delegationEvidence *DelegationEvidence) bool {

	timeNotBefore := time.Unix(delegationEvidence.NotBefore, 0)
	timeNotOnOrAfter := time.Unix(delegationEvidence.NotOnOrAfter, 0)
	timeNow := time.Now()

	if !timeNow.Before(timeNotBefore) && !timeNow.After(timeNotOnOrAfter) && !timeNow.Equal(timeNotOnOrAfter) {
		return true
	}
	logger.Info("The retrieved delegation evidence is not active anymore.")
	return false
}

type iShareDecider struct{}
