package ishare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"

	client "github.com/fiware/dsba-pdp/http"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
)

var logger = logging.Log()
var globalHttpClient = client.HttpClient()

const IShareEnabledVar = "ISHARE_ENABLED"
const CertificatePathVar = "ISHARE_CERTIFICATE_PATH"
const KeyPathVar = "ISHARE_KEY_PATH"
const IShareClientIdVar = "ISHARE_CLIENT_ID"
const AuthorizationRegistryIdVar = "ISHARE_AR_ID"
const AuthorizationRegistryUrlVar = "ISHARE_AUTHORIZATION_REGISTRY_URL"
const ArDelegationPathVar = "ISHARE_DELEGATION_PATH"
const ArTokenPathVar = "ISHARE_TOKEN_PATH"

type AuthorizationRegistry interface {
	GetPDPRegistry() *model.AuthorizationRegistry
	GetDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]model.Policy, authorizationRegistry *model.AuthorizationRegistry) (delegeationEvidence *model.DelegationEvidence, httpErr model.HttpError)
}

type IShareAuthorizationRegistry struct {

	/**
	* Authorization registry of the PDP, e.g. where should we get "our" policies from.
	 */
	pdpRegistry model.AuthorizationRegistry
	/**
	* The token parser for parsing and validating the JWT
	 */
	tokenHandler *TokenHandler
}

/**
* Client id of the pdp in the iShare context. Will be used when requesting the authorization registry.
 */
var iShareClientId string

var defaultTokenPath string = "/connect/token"
var defaultDelegationPath string = "/delegation"

/**
* Init reades and decodes the key and certificate to be used when contacting the AR
 */
func NewIShareAuthorizationRegistry() (registry *IShareAuthorizationRegistry) {
	ishareEnabled, err := strconv.ParseBool(os.Getenv(IShareEnabledVar))

	if err != nil || !ishareEnabled {
		logger.Fatalf("iShare is not enabled.")
		return
	} else {

		iShareClientId = os.Getenv(IShareClientIdVar)
		iShareARId := os.Getenv(AuthorizationRegistryIdVar)
		iShareARUrl := os.Getenv(AuthorizationRegistryUrlVar)

		delegationPathEnv := os.Getenv(ArDelegationPathVar)
		tokenPathEnv := os.Getenv(ArTokenPathVar)

		if iShareClientId == "" {
			logger.Fatal("No client id for the pdp was provided.")
			return
		}

		pdpAuthorizationRegistry := model.AuthorizationRegistry{}

		if iShareARId == "" {
			logger.Fatal("No id for the authorization registry was provided.")
			return
		}
		pdpAuthorizationRegistry.Id = iShareARId

		if iShareARUrl == "" {
			logger.Fatal("No URL for the authorization registry was provided.")
			return
		}
		pdpAuthorizationRegistry.Host = iShareARUrl

		if delegationPathEnv != "" {
			pdpAuthorizationRegistry.DelegationPath = delegationPathEnv
		} else {
			pdpAuthorizationRegistry.DelegationPath = defaultDelegationPath
		}
		logger.Infof("Will use the delegtion address %s.", pdpAuthorizationRegistry.GetDelegationAddress())

		if tokenPathEnv != "" {
			pdpAuthorizationRegistry.TokenPath = tokenPathEnv
		} else {
			pdpAuthorizationRegistry.TokenPath = defaultTokenPath
		}
		logger.Infof("Will use the token address %s.", pdpAuthorizationRegistry.GetTokenAddress())

		tokenHandler := NewTokenHandler()

		return &IShareAuthorizationRegistry{pdpRegistry: pdpAuthorizationRegistry, tokenHandler: tokenHandler}
	}
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) GetPDPRegistry() *model.AuthorizationRegistry {
	return &iShareAuthRegistry.pdpRegistry
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) GetDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]model.Policy, authorizationRegistry *model.AuthorizationRegistry) (delegeationEvidence *model.DelegationEvidence, httpErr model.HttpError) {

	accessToken, httpErr := iShareAuthRegistry.tokenHandler.GetTokenFromAR(authorizationRegistry)

	if httpErr != (model.HttpError{}) {
		logger.Warn("Was not able to get an access token.", httpErr)
		return delegeationEvidence, httpErr
	}

	logger.Debugf("Token: %s", accessToken)

	delegationRequestBody := model.DelegationRequestWrapper{DelegationRequest: &model.DelegationRequest{PolicyIssuer: issuer, Target: &model.DelegationTarget{AccessSubject: delegationTarget}, PolicySets: []*model.PolicySet{{Policies: *requiredPolicies}}}}
	jsonBody, err := json.Marshal(delegationRequestBody)
	if err != nil {
		return delegeationEvidence, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to create a delegation request.", RootError: err}
	}

	logger.Debugf("Delegation request: %s", jsonBody)
	logger.Debugf("Delegation address: %s", authorizationRegistry.GetDelegationAddress())

	policyRequest, err := http.NewRequest("POST", authorizationRegistry.GetDelegationAddress(), bytes.NewReader(jsonBody))
	if err != nil {
		logger.Debug("Was not able to create the delegation request.")
		return delegeationEvidence, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to create delegation request.", RootError: err}

	}

	policyRequest.Header.Set("Authorization", "Bearer "+accessToken)
	policyRequest.Header.Set("Content-Type", "application/json")

	delegationResponse, err := globalHttpClient.Do(policyRequest)
	if err != nil || delegationResponse == nil {
		logger.Debugf("Was not able to retrieve policies from %s, error is %v", authorizationRegistry.GetDelegationAddress(), err)
		return delegeationEvidence, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to get a delegation response.", RootError: err}
	}

	if delegationResponse.StatusCode != 200 && delegationResponse.StatusCode == 404 {
		logger.Debugf("No policies found for issuer %s and subject %s at %s.", issuer, delegationTarget, authorizationRegistry.GetDelegationAddress())
		return delegeationEvidence, model.HttpError{Status: http.StatusNotFound, Message: fmt.Sprintf("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), RootError: nil}
	} else if delegationResponse.StatusCode != 200 {
		logger.Debugf("Received a %d from the ar.", delegationResponse.StatusCode)
		return delegeationEvidence, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), RootError: nil}
	}
	if delegationResponse.Body == nil {
		logger.Debug("Received an empty body from the ar.")
		return delegeationEvidence, model.HttpError{Status: http.StatusBadGateway, Message: "Did not receive a response body from the ar.", RootError: nil}
	}

	// decode and return
	var delegationResponseObject model.DelegationResponse
	err = json.NewDecoder(delegationResponse.Body).Decode(&delegationResponseObject)
	if err != nil {
		logger.Debugf("Was not able to decode the response body. Error: %v", err)
		return delegeationEvidence, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Received an invalid body from the ar: %s", delegationResponse.Body), RootError: err}
	}

	parsedToken, httpErr := iShareAuthRegistry.tokenHandler.ParseIShareToken(delegationResponseObject.DelegationToken)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to decode the ar response. Error: %v", httpErr)
		return delegeationEvidence, httpErr
	}
	logger.Debugf("Delegation response: %v", logging.PrettyPrintObject(parsedToken.DelegationEvidence))

	return &parsedToken.DelegationEvidence, httpErr
}
