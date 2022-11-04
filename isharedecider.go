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

var ngsiPathIndicator string = "/ngsi-ld/v1/entities"

func (iShareDecider) Decide(token string, originalAddress string, requestType string, requestBody *map[string]interface{}) (decision Decision, httpErr httpError) {

	// verification should already have happend, pdp only decides based on the presented information
	//parsedToken, httpErr := parseIShareToken(token)
	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(token, &IShareToken{})
	if err != nil {
		return decision, httpError{http.StatusUnauthorized, "No proper jwt was provided", err}
	}

	if httpErr != (httpError{}) {
		return decision, httpError{http.StatusUnauthorized, httpErr.message, &httpErr}
	}
	parsedToken := unverifiedToken.Claims.(*IShareToken)

	issuer := parsedToken.Issuer
	subject := parsedToken.Subject

	delegationEvidence := &parsedToken.DelegationEvidence

	// issuer is required, so we take it as an indicator, since we cannot compare in-depth(due to the embedded slice)
	if delegationEvidence.PolicyIssuer == "" {
		requiredPolicies, httpErr := buildRequiredPolicies(originalAddress, requestType, requestBody)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}

		delegationEvidence, httpErr = getDelegationEvidence(iShareClientId, issuer, requiredPolicies)
		if httpErr != (httpError{}) {
			return decision, httpErr
		}
	}

	if !isActive(delegationEvidence) {
		return Decision{false, fmt.Sprintf("DelegationEvidence for issuer %s and subject %s is not inside a valid time range.", issuer, subject)}, httpErr
	}

	return Decision{false, "Everything ok, now we need to verfiy the policies."}, httpErr
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
	return []Policy{{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}, Environment: Environment{ServiceProviders: []string{}}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr

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
	return []Policy{{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}, Environment: Environment{ServiceProviders: []string{}}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr
}

func buildRequiredPoliciesForAttrs(entityId string, requestType string, requestBody *map[string]interface{}) (policies []Policy, httpErr httpError) {

	if requestType != "POST" && requestType != "PATCH" {
		return policies, httpError{http.StatusBadRequest, fmt.Sprintf("%s is not supported on /attrs.", requestType), nil}
	}

	resource := Resource{
		Type:        (*requestBody)["type"].(string),
		Identifiers: []string{entityId},
		Attributes:  getAttributesFromBody(requestBody)}

	return []Policy{{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}, Environment: Environment{ServiceProviders: []string{}}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr
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

	return []Policy{{Target: PolicyTarget{Resource: resource, Actions: []string{requestType}, Environment: Environment{ServiceProviders: []string{}}}, Rules: []Rule{{Effect: "Permit"}}}}, httpErr

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
			return nil, err
		}
		clientCert, err := x509.ParseCertificate(decodedClientCert)
		if err != nil {
			return nil, err
		}

		rootPool := x509.NewCertPool()
		for i, cert := range x5cInterfaces {
			if i == 0 {
				// skip client cert
				continue
			}
			decodedClientCert, err := base64.StdEncoding.DecodeString(cert.(string))
			if err != nil {
				return nil, err
			}
			parsedCert, err := x509.ParseCertificate(decodedClientCert)
			if err != nil {
				return nil, err
			}
			rootPool.AddCert(parsedCert)
		}

		opts := x509.VerifyOptions{Roots: rootPool}
		if _, err := clientCert.Verify(opts); err != nil {
			return nil, err
		}
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

	logger.Debugf("The retrieved delegation evidence is not active anymore. IsNotBefore: %v IsNotAfter: %v IsNotNow: %v", isNotBefore, isNotAfter, isNotNow)
	return false
}

type iShareDecider struct{}
