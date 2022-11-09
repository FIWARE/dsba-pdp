package main

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/google/uuid"
)

/**
* Expiry of the accesstoken. Has to be 30s according to the iShare specification.
 */
var tokenExpiryInS = 30

/**
 * Global folder accessor
 */
var ishareFolderAccessor folderAccessor = folderAccessor{getFolderContent}

/**
 * Global file accessor
 */
var ishareFileAccessor fileAccessor = fileAccessor{writeFile, readFile}

/**
* Array of the encoded certificates, formatted according to the iShare spec.
 */
var certificateArray []string

/**
* The RSA key for signing accesstokens
 */
var signingKey *rsa.PrivateKey

/**
* Client id of the pdp in the iShare context. Will be used when requesting the authorization registry.
 */
var iShareClientId string

var defaultTokenPath string = "/connect/token"
var defaultDelegationPath string = "/delegation"

/**
* Authorization registry of the PDP, e.g. where should we get "our" policies from.
 */
var PDPAuthorizationRegistry AuthorizationRegistry

/**
* Init reades and decodes the key and certificate to be used when contacting the AR
 */
func init() {
	ishareEnabled, err := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))

	if err != nil || !ishareEnabled {
		logger.Info("iShare is not enabled.")
		return
	}

	certificatePath := os.Getenv("ISHARE_CERTIFICATE_PATH")
	keyPath := os.Getenv("ISHARE_KEY_PATH")
	iShareClientId = os.Getenv("ISHARE_CLIENT_ID")
	iShareARId := os.Getenv("ISHARE_AR_ID")
	iShareARUrl := os.Getenv("ISHARE_AUTHORIZATION_REGISTRY_URL")

	delegationPathEnv := os.Getenv("ISHARE_DELEGATION_PATH")
	tokenPathEnv := os.Getenv("ISHARE_TOKEN_PATH")

	if certificatePath == "" {
		logger.Fatal("Did not receive a valid certificate path.")
	}

	if keyPath == "" {
		logger.Fatal("Did not receive a valid key path.")
	}

	if iShareClientId == "" {
		logger.Fatal("No client id for the pdp was provided.")
	}

	PDPAuthorizationRegistry = AuthorizationRegistry{}

	if iShareARUrl == "" {
		logger.Fatal("No URL for the authorization registry was provided.")
	}
	PDPAuthorizationRegistry.Host = iShareARUrl

	if iShareARId == "" {
		logger.Fatal("No id for the authorization registry was provided.")
	}
	PDPAuthorizationRegistry.Id = iShareARId

	if delegationPathEnv != "" {
		PDPAuthorizationRegistry.DelegationPath = delegationPathEnv
	} else {
		PDPAuthorizationRegistry.DelegationPath = defaultDelegationPath
	}
	logger.Infof("Will use the delegtion address %s.", PDPAuthorizationRegistry.getDelegationAddress())

	if tokenPathEnv != "" {
		PDPAuthorizationRegistry.TokenPath = tokenPathEnv
	} else {
		PDPAuthorizationRegistry.TokenPath = defaultTokenPath
	}
	logger.Infof("Will use the token address %s.", PDPAuthorizationRegistry.getTokenAddress())

	signingKey, err = getSigningKey(keyPath)
	if err != nil {
		logger.Fatalf("Was not able to read the rsa private key from %s", keyPath, err)
	}

	certificateArray, err = getCertificateArray(certificatePath)
	if err != nil {
		logger.Fatalf("Was not able to read the certificate from %s", certificatePath, err)
	}
}

func getDelegationEvidence(issuer string, delegationTarget string, requiredPolicies *[]Policy, authorizationRegistry *AuthorizationRegistry) (delegeationEvidence *DelegationEvidence, httpErr httpError) {

	accessToken, httpErr := getTokenFromAR(authorizationRegistry)

	if httpErr != (httpError{}) {
		logger.Warn("Was not able to get an access token.", httpErr)
		return delegeationEvidence, httpErr
	}

	logger.Debugf("Token: %s", accessToken)

	delegationRequestBody := DelegationRequestWrapper{&DelegationRequest{PolicyIssuer: issuer, Target: &DelegationTarget{AccessSubject: delegationTarget}, PolicySets: []*PolicySet{{Policies: *requiredPolicies}}}}
	jsonBody, err := json.Marshal(delegationRequestBody)
	if err != nil {
		return delegeationEvidence, httpError{http.StatusInternalServerError, "Was not able to create a delegation request.", err}
	}

	logger.Debugf("Delegation request: %s", jsonBody)
	logger.Debugf("Delegation address: %s", authorizationRegistry.getDelegationAddress())

	policyRequest, err := http.NewRequest("POST", authorizationRegistry.getDelegationAddress(), bytes.NewReader(jsonBody))
	if err != nil {
		logger.Debug("Was not able to create the delegation request.")
		return delegeationEvidence, httpError{http.StatusInternalServerError, "Was not able to create delegation request.", err}

	}

	policyRequest.Header.Set("Authorization", "Bearer "+accessToken)
	policyRequest.Header.Set("Content-Type", "application/json")

	delegationResponse, err := globalHttpClient.Do(policyRequest)
	if err != nil {
		logger.Debugf("Was not able to retrieve policies from %s, error is %v", authorizationRegistry.getDelegationAddress(), err)
		return delegeationEvidence, httpError{http.StatusBadGateway, "Was not able to get a delegation response.", err}
	}

	if delegationResponse.StatusCode != 200 && delegationResponse.StatusCode == 404 {
		logger.Debugf("No policies found for issuer %s and subject %s at %s.", issuer, delegationTarget, authorizationRegistry.getDelegationAddress())
		return delegeationEvidence, httpError{http.StatusForbidden, fmt.Sprintf("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), nil}
	} else if delegationResponse.StatusCode != 200 {
		logger.Debugf("Received a %s from the ar.", delegationResponse.StatusCode)
		return delegeationEvidence, httpError{http.StatusBadGateway, fmt.Sprintf("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), nil}
	}
	if delegationResponse.Body == nil {
		logger.Debug("Received an empty body from the ar.")
		return delegeationEvidence, httpError{http.StatusBadGateway, "Did not receive a response body from the ar.", nil}
	}

	// decode and return
	var delegationResponseObject DelegationResponse
	err = json.NewDecoder(delegationResponse.Body).Decode(&delegationResponseObject)
	if err != nil {
		logger.Debugf("Was not able to decode the response body. Error: %v", err)
		return delegeationEvidence, httpError{http.StatusBadGateway, fmt.Sprintf("Received an invalid body from the ar: %s", delegationResponse.Body), err}
	}

	parsedToken, httpErr := parseIShareToken(delegationResponseObject.DelegationToken)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to decode the ar response. Error: %v", err)
		return delegeationEvidence, httpErr
	}
	logger.Debugf("Delegation response: %v", prettyPrintObject(parsedToken.DelegationEvidence))

	return &parsedToken.DelegationEvidence, httpErr
}

func getTokenFromAR(authorizationRegistry *AuthorizationRegistry) (accessToken string, httpErr httpError) {

	signedToken, err := generateSignedToken(authorizationRegistry.Id, iShareClientId)
	if err != nil {
		httpErr = httpError{http.StatusInternalServerError, "Was not able to generate a signed token.", err}
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
	tokenResponse, err := globalHttpClient.PostForm(authorizationRegistry.getTokenAddress(), requestData)
	if err != nil {
		logger.Debugf("Failed to get token response from ar at: %s", authorizationRegistry.getTokenAddress())
		return accessToken, httpError{http.StatusBadGateway, "Was not able to get the token from the idp.", err}

	}

	if tokenResponse.Body == nil {
		logger.Debugf("Failed to decode token response from ar at: %s", authorizationRegistry.getTokenAddress())
		return accessToken, httpError{http.StatusBadGateway, "Did not receive a valid body from the idp.", err}

	}

	// decode and return
	var decodedResponse map[string]interface{}
	err = json.NewDecoder(tokenResponse.Body).Decode(&decodedResponse)
	if err != nil {
		return accessToken, httpError{http.StatusBadGateway, "Was not able to decode idp response.", err}

	}

	if decodedResponse == nil || decodedResponse["access_token"] == nil {
		return accessToken, httpError{http.StatusBadGateway, fmt.Sprintf("Did not receive an access token from the idp. Resp: %v", decodedResponse), err}
	}

	return decodedResponse["access_token"].(string), httpErr
}

func generateSignedToken(arId string, clientId string) (signedToken string, err error) {

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
	jwtToken.Header["x5c"] = certificateArray

	// sign the token
	signedToken, err = jwtToken.SignedString(signingKey)
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
	priv, err := ishareFileAccessor.read(keyPath)
	if err != nil {
		logger.Warn("Was not able to read the key file from %s.", keyPath, err)
		return key, err
	}

	// parse key file
	key, err = jwt.ParseRSAPrivateKeyFromPEM(priv)
	if err != nil {
		logger.Warn("Was not able to parse the key %s.", priv, err)
		return key, err
	}

	return
}

/**
* Read the certificate(chain) and translate it into the iShare-compatible array of certificates
 */
func getCertificateArray(certificatePath string) (encodedCert []string, err error) {
	// read certificate file
	cert, err := ishareFileAccessor.read(certificatePath)
	if err != nil {
		logger.Warnf("Was not able to read the certificate file from %s.", certificatePath, err)
		return encodedCert, err
	}
	derArray := []string{}

	for block, rest := pem.Decode(cert); block != nil; block, rest = pem.Decode(rest) {
		switch block.Type {
		case "CERTIFICATE":
			// check that its a parsable certificate, only done on startup e.g. not performance critical
			_, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				logger.Warnf("Was not able to parse the certificat from %s.", certificatePath, err)
				return encodedCert, err
			}
			derArray = append(derArray, base64.StdEncoding.EncodeToString(block.Bytes))
		default:
			logger.Infof("Received unexpected block %s.", block.Type)
			return encodedCert, fmt.Errorf("unexpected-block")
		}
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

type folderContentGetter func(path string) (folders []fs.FileInfo, err error)
type folderAccessor struct {
	get folderContentGetter
}

type fileWriter func(path string, content []byte, fileMode fs.FileMode) (err error)
type fileReader func(filename string) (content []byte, err error)

type fileAccessor struct {
	write fileWriter
	read  fileReader
}

func getFolderContent(path string) (folders []fs.FileInfo, err error) {
	return ioutil.ReadDir(path)
}

func writeFile(path string, content []byte, fileMode fs.FileMode) (err error) {
	return ioutil.WriteFile(path, content, fileMode)
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
