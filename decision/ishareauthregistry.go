package decision

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
	client "github.com/wistefan/dsba-pdp/http"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
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
	* The RSA key for signing accesstokens
	 */
	signingKey *rsa.PrivateKey
	/**
	 * Array of the encoded certificates, formatted according to the iShare spec.
	 */
	certificateArray []string
	/**
	* Authorization registry of the PDP, e.g. where should we get "our" policies from.
	 */
	pdpRegistry model.AuthorizationRegistry
	/**
	* The token parser for parsing and validating the JWT
	 */
	tokenParser TokenParser
}

/**
* Expiry of the accesstoken. Has to be 30s according to the iShare specification.
 */
var tokenExpiryInS = 30

/**
 * Global file accessor
 */
var ishareFileAccessor fileAccessor = diskFileAccessor{}

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

		certificatePath := os.Getenv(CertificatePathVar)
		keyPath := os.Getenv(KeyPathVar)
		iShareClientId = os.Getenv(IShareClientIdVar)
		iShareARId := os.Getenv(AuthorizationRegistryIdVar)
		iShareARUrl := os.Getenv(AuthorizationRegistryUrlVar)

		delegationPathEnv := os.Getenv(ArDelegationPathVar)
		tokenPathEnv := os.Getenv(ArTokenPathVar)

		if certificatePath == "" {
			logger.Fatal("Did not receive a valid certificate path.")
			return
		}

		if keyPath == "" {
			logger.Fatal("Did not receive a valid key path.")
			return
		}

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

		signingKey, err := getSigningKey(keyPath)
		if err != nil {
			logger.Fatalf("Was not able to read the rsa private key from %s, err: %v", keyPath, err)
			return
		}

		certificateArray, err := getCertificateArray(certificatePath)
		if err != nil {
			logger.Fatalf("Was not able to read the certificate from %s, err: %v", certificatePath, err)
			return
		}
		tokenParser := TokenParser{RealClock{}}

		return &IShareAuthorizationRegistry{signingKey: signingKey, certificateArray: certificateArray, pdpRegistry: pdpAuthorizationRegistry, tokenParser: tokenParser}
	}
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) GetPDPRegistry() *model.AuthorizationRegistry {
	return &iShareAuthRegistry.pdpRegistry
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) GetDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]model.Policy, authorizationRegistry *model.AuthorizationRegistry) (delegeationEvidence *model.DelegationEvidence, httpErr model.HttpError) {

	accessToken, httpErr := iShareAuthRegistry.getTokenFromAR(authorizationRegistry)

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
		return delegeationEvidence, model.HttpError{Status: http.StatusForbidden, Message: fmt.Sprintf("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), RootError: nil}
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

	parsedToken, httpErr := iShareAuthRegistry.tokenParser.parseIShareToken(delegationResponseObject.DelegationToken)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to decode the ar response. Error: %v", httpErr)
		return delegeationEvidence, httpErr
	}
	logger.Debugf("Delegation response: %v", logging.PrettyPrintObject(parsedToken.DelegationEvidence))

	return &parsedToken.DelegationEvidence, httpErr
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) getTokenFromAR(authorizationRegistry *model.AuthorizationRegistry) (accessToken string, httpErr model.HttpError) {

	signedToken, err := iShareAuthRegistry.generateSignedToken(authorizationRegistry.Id, iShareClientId)
	if err != nil {
		httpErr = model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to generate a signed token.", RootError: err}
		return
	}

	// prepare the form-body
	requestData := url.Values{
		"grant_type":            {"client_credentials"},
		"scope":                 {"iSHARE"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {signedToken},
		"client_id":             {iShareClientId},
	}

	// get the token
	tokenResponse, err := globalHttpClient.PostForm(authorizationRegistry.GetTokenAddress(), requestData)
	if err != nil {
		logger.Debugf("Failed to get token response from ar at: %s", authorizationRegistry.GetTokenAddress())
		return accessToken, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to get the token from the idp.", RootError: err}

	}

	if tokenResponse == nil || tokenResponse.StatusCode != 200 || tokenResponse.Body == nil {
		if tokenResponse.Body != nil {
			logger.Debugf("Response body was %s.", tokenResponse.Body)
		}
		logger.Debugf("Failed to decode token response from ar at: %s", authorizationRegistry.GetTokenAddress())
		return accessToken, model.HttpError{Status: http.StatusBadGateway, Message: "Did not receive a valid body from the idp.", RootError: err}

	}

	// decode and return
	var decodedResponse map[string]interface{}
	err = json.NewDecoder(tokenResponse.Body).Decode(&decodedResponse)
	if err != nil {
		return accessToken, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to decode idp response.", RootError: err}

	}

	if decodedResponse == nil || decodedResponse["access_token"] == nil {
		return accessToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive an access token from the idp. Resp: %v", decodedResponse), RootError: err}
	}

	return decodedResponse["access_token"].(string), httpErr
}

func (iShareAuthRegistry *IShareAuthorizationRegistry) generateSignedToken(arId string, clientId string) (signedToken string, err error) {

	randomUuid, err := uuid.NewRandom()
	if err != nil {
		logger.Warn("Was not able to generate a uuid to be used as jti.", err)
		return
	}

	// prepare token headers
	now := time.Now().Unix()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": randomUuid.String(),
		"iss": clientId,
		"sub": clientId,
		"aud": arId,
		"iat": now,
		"exp": now + int64(tokenExpiryInS),
	})

	// set the certificate(s) to the header
	jwtToken.Header["x5c"] = iShareAuthRegistry.certificateArray

	defer func() {

		if panicErr := recover(); panicErr != nil {
			logger.Warnf("An invalid key was configured: %v. Err: %s", iShareAuthRegistry.signingKey, panicErr)
			err = errors.New("invalid_key_configured")
		}
	}()
	logger.Debugf("T %v", iShareAuthRegistry.signingKey)
	// sign the token
	signedToken, err = jwtToken.SignedString(iShareAuthRegistry.signingKey)
	if err != nil {
		logger.Warn("Was not able to sign the token.", err)
		return
	}
	return
}

/**
* Read siging key from local filesystem
 */
func getSigningKey(keyPath string) (key *rsa.PrivateKey, err error) {
	// read key file
	priv, err := ishareFileAccessor.ReadFile(keyPath)
	if err != nil {
		logger.Warnf("Was not able to read the key file from %s. err: %v", keyPath, err)
		return key, err
	}

	// parse key file
	key, err = jwt.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		logger.Warnf("Was not able to parse the key %s. err: %v", priv, err)
		return key, err
	}

	return
}

/**
* Read the certificate(chain) and translate it into the iShare-compatible array of certificates
 */
func getCertificateArray(certificatePath string) (encodedCert []string, err error) {
	// read certificate file
	cert, err := ishareFileAccessor.ReadFile(certificatePath)
	if err != nil {
		logger.Warnf("Was not able to read the certificate file from %s. err: %v", certificatePath, err)
		return encodedCert, err
	}
	derArray := []string{}
	for block, rest := pem.Decode(cert); block != nil; block, rest = pem.Decode(rest) {
		logger.Debugf("Current block is of type %s.", block.Type)
		switch block.Type {
		case "CERTIFICATE":
			// check that its a parsable certificate, only done on startup e.g. not performance critical
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Warnf("Was not able to parse the certificat from %s. err: %v", certificatePath, err)
				return encodedCert, err
			}
			derArray = append(derArray, base64.StdEncoding.EncodeToString(block.Bytes))
		default:
			logger.Infof("Received unexpected block %s.", block.Type)
			return encodedCert, fmt.Errorf("unexpected_block")
		}
	}
	if len(derArray) == 0 {
		return derArray, errors.New("no_certificate_found")
	}

	return derArray, err
}

/**
* Helper method to delete empty strings from the arry
 */
func deleteEmpty(arrayToClean []string) (cleanedArray []string) {
	for _, str := range arrayToClean {
		if str != "" {
			cleanedArray = append(cleanedArray, str)
		}
	}
	return
}

// file system interfaces

// Interface to the http-client
type fileAccessor interface {
	ReadFile(filename string) ([]byte, error)
}
type diskFileAccessor struct{}

func (diskFileAccessor) ReadFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
