package main

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

/**
* Begin certificate line in an PEM-encoded certificate
 */
var certificateBeginLine = "-----BEGIN CERTIFICATE-----\n"

/**
* End certificate line in an PEM-encoded certificate
 */
var certificateEndLine = "-----END CERTIFICATE-----\n"

/**
* Expiry of the accesstoken. Has to be 30s according to the iShare specification.
 */
var tokenExpiryInS = 30

/**
* Global filesystem accessor
 */
var diskFs fileSystem = &osFS{}

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

/**
* Id of the authorization registry. Will be used in the audience parameter.
 */
var iShareARId string

/**
* Id of the authorization registry. Will be used in the audience parameter.
 */
var iShareARUrl string

var defaultTokenPath string = "/connect/token"
var defaultDelegationPath string = "/delegation"

var tokenAddress string
var delegationAddress string

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
	iShareClientId := os.Getenv("ISHARE_CLIENT_ID")
	iShareARId := os.Getenv("ISHARE_AR_ID")
	iShareARUrl = os.Getenv("ISHARE_AUTHORIZATION_REGISTRY_URL")

	delegationPathEnv := os.Getenv("ISHARE_DELEGATION_PATH")
	tokenPathEnv := os.Getenv("ISHARE_TOKEN_PATH")

	if certificatePath == "" {
		logger.Fatal("Did not receive a valid certificate path.")
	}

	if keyPath == "" {
		logger.Fatal("Did not receive a valid key path.")
	}

	if iShareARUrl == "" {
		logger.Fatal("No URL for the authorization registry was provided.")
	}

	if iShareARId == "" {
		logger.Fatal("No id for the authorization registry was provided.")
	}

	if iShareClientId == "" {
		logger.Fatal("No client id for the pdp was provided.")
	}

	if delegationPathEnv != "" {
		delegationAddress = iShareARUrl + delegationPathEnv
	} else {
		delegationAddress = iShareARUrl + defaultDelegationPath
	}
	logger.Infof("Will use the delegtion address %s.", delegationAddress)

	if tokenPathEnv != "" {
		tokenAddress = iShareARUrl + tokenPathEnv
	} else {
		tokenAddress = iShareARUrl + defaultTokenPath
	}
	logger.Infof("Will use the token address %s.", tokenAddress)

	signingKey, err = getSigningKey(keyPath)
	if err != nil {
		logger.Fatalf("Was not able to read the rsa private key from %s", keyPath, err)
	}

	certificateArray, err = getCertificateArray(certificatePath)
	if err != nil {
		logger.Fatalf("Was not able to read the certificate from %s", certificatePath, err)
	}
}

func getDelegationEvidence(issuer string, delegationTarget string, requiredPolicies []Policy) (delegeationEvidence *DelegationEvidence, httpErr httpError) {

	accessToken, httpErr := getTokenFromAR()

	if httpErr != (httpError{}) {
		logger.Warn("Was not able to an access token.", httpErr)
		return delegeationEvidence, httpErr
	}

	delegationRequestBody := DelegationRequest{PolicyIssuer: issuer, Target: DelegationTarget{AccessSubject: delegationTarget}, PolicySets: []PolicySet{PolicySet{Policies: requiredPolicies}}}
	jsonBody, err := json.Marshal(delegationRequestBody)
	if err != nil {
		return delegeationEvidence, httpError{http.StatusInternalServerError, "Was not able to create a delegation request.", err}
	}

	policyRequest, err := http.NewRequest("POST", delegationAddress, bytes.NewReader(jsonBody))

	policyRequest.Header.Set("Authorization", "Bearer "+accessToken)
	policyRequest.Header.Set("Content-Type", "application/json")

	delegationResponse, err := globalHttpClient.Do(policyRequest)
	if err != nil {
		return delegeationEvidence, httpError{http.StatusBadGateway, "Was not able to get a delegation response.", err}
	}

	if delegationResponse.StatusCode != 200 {
		logger.Warn()
		return delegeationEvidence, httpError{http.StatusBadGateway, fmt.Sprint("Did not receive an ok from the ar. Status was: %v", delegationResponse.StatusCode), nil}
	}
	if delegationResponse.Body == nil {
		return delegeationEvidence, httpError{http.StatusBadGateway, "Did not receive a response body from the ar.", nil}
	}

	// decode and return
	err = json.NewDecoder(delegationResponse.Body).Decode(&delegeationEvidence)
	if err != nil {
		return delegeationEvidence, httpError{http.StatusBadGateway, fmt.Sprint("Received an invalid body from the ar: %s", delegationResponse.Body), err}
	}
	return delegeationEvidence, httpErr
}

func getTokenFromAR() (accessToken string, httpErr httpError) {

	signedToken, err := generateSignedToken()
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
	tokenResponse, err := globalHttpClient.PostForm(tokenAddress, requestData)
	if err != nil {
		return accessToken, httpError{http.StatusBadGateway, "Was not able to get the token from the idp.", err}

	}

	if tokenResponse.Body == nil {
		logger.Warn()
		return accessToken, httpError{http.StatusBadGateway, "Did not receive a valid body from the idp.", err}

	}

	// decode and return
	var decodedResponse map[string]interface{}
	err = json.NewDecoder(tokenResponse.Body).Decode(&decodedResponse)
	if err != nil {
		return accessToken, httpError{http.StatusBadGateway, "Was not able to decode idp response.", err}

	}

	if decodedResponse == nil || decodedResponse["access_token"] == nil {
		return accessToken, httpError{http.StatusBadGateway, fmt.Sprint("Did not receive an access token from the idp. Resp: %v", decodedResponse), err}
	}

	return decodedResponse["access_token"].(string), httpErr
}

func generateSignedToken() (signedToken string, err error) {

	randomUuid, err := uuid.NewRandom()
	if err != nil {
		logger.Warn("Was not able to generate a uuid to be used as jti.", err)
		return
	}

	// prepare token headers
	now := time.Now().Unix()
	jwtToken := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
		"jti": randomUuid.String(),
		"iss": iShareClientId,
		"sub": iShareClientId,
		"aud": iShareARId,
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
		logger.Warn("Was not able to read the certificate file from %s.", certificatePath, err)
		return encodedCert, err
	}

	certString := strings.ReplaceAll(string(cert), certificateEndLine, "")
	certArray := strings.Split(certString, certificateBeginLine)

	for i := range certArray {
		certArray[i] = strings.ReplaceAll(certArray[i], certificateEndLine, "")
	}

	certArray = deleteEmpty(certArray)

	return
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

type fileSystem interface {
	Open(name string) (file, error)
	Stat(name string) (os.FileInfo, error)
	MkdirAll(path string, perm fs.FileMode) error
	RemoveAll(path string) error
}

type file interface {
	io.Closer
	io.Reader
	io.ReaderAt
	io.Seeker
	Stat() (os.FileInfo, error)
}

type osFS struct{}

func (osFS) Open(name string) (file, error)               { return os.Open(name) }
func (osFS) Stat(name string) (os.FileInfo, error)        { return os.Stat(name) }
func (osFS) MkdirAll(path string, perm fs.FileMode) error { return os.MkdirAll(path, perm) }
func (osFS) RemoveAll(path string) error                  { return os.RemoveAll(path) }

func getFolderContent(path string) (folders []fs.FileInfo, err error) {
	return ioutil.ReadDir(path)
}

func writeFile(path string, content []byte, fileMode fs.FileMode) (err error) {
	return ioutil.WriteFile(path, content, fileMode)
}

func readFile(filename string) ([]byte, error) {
	return ioutil.ReadFile(filename)
}
