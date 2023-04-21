package ishare

import (
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
	"time"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
)

/**
* Expiry of the accesstoken. Has to be 30s according to the iShare specification.
 */
var tokenExpiryInS = 30

/**
 * Global file accessor
 */
var ishareFileAccessor fileAccessor = diskFileAccessor{}

type TokenHandler struct {
	/**
	* Repository to get the trusted participants from
	 */
	trustedParticipantRepository TrustedParticipantRepository
	/**
	* The RSA key for signing accesstokens
	 */
	signingKey *rsa.PrivateKey
	/**
	 * Array of the encoded certificates, formatted according to the iShare spec.
	 */
	certificateArray []string
	/**
	* Clock interface for validating tokens
	 */
	Clock Clock
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (c RealClock) Now() time.Time {
	return time.Now()
}

func NewTokenHandler() (tokenHandler *TokenHandler) {
	tokenHandler = new(TokenHandler)

	certificatePath := os.Getenv(CertificatePathVar)
	keyPath := os.Getenv(KeyPathVar)
	if certificatePath == "" {
		logger.Fatal("Did not receive a valid certificate path.")
		return
	}

	if keyPath == "" {
		logger.Fatal("Did not receive a valid key path.")
		return
	}
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

	tokenHandler.signingKey = signingKey
	tokenHandler.certificateArray = certificateArray

	tokenHandler.Clock = RealClock{}

	trustedParticipantRepository := NewTrustedParticipantRepository(tokenHandler.GetTokenFromAR, tokenHandler.ParseTrustedListToken)
	tokenHandler.trustedParticipantRepository = trustedParticipantRepository

	return tokenHandler

}

func (th *TokenHandler) ParseIShareToken(tokenString string) (parsedToken *model.IShareToken, httpErr model.HttpError) {
	token, err := jwt.ParseWithClaims(tokenString, &model.IShareToken{}, func(t *jwt.Token) (interface{}, error) {
		return th.GetKeyFromToken(t)
	})

	if err != nil {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Was not able to parse token. Error: %v", err), RootError: err}
	}
	if !token.Valid {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive a valid token. Error: %v", err), RootError: err}
	}
	return token.Claims.(*model.IShareToken), httpErr

}

func (th *TokenHandler) ParseTrustedListToken(tokenString string) (parsedToken *model.TrustedListToken, httpErr model.HttpError) {
	token, err := jwt.ParseWithClaims(tokenString, &model.TrustedListToken{}, func(t *jwt.Token) (interface{}, error) {
		return th.GetKeyFromToken(t)
	})
	if err != nil {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Was not able to parse token. Error: %v", err), RootError: err}
	}
	if !token.Valid {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive a valid token. Error: %v", err), RootError: err}
	}
	return token.Claims.(*model.TrustedListToken), httpErr
}

func (th *TokenHandler) GetKeyFromToken(token *jwt.Token) (key *rsa.PublicKey, err error) {

	if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
		return nil, fmt.Errorf("invalid_token_method")
	}

	x5cInterfaces := (*token).Header["x5c"].([]interface{})
	// the first in the chain is the client cert
	decodedClientCert, err := base64.StdEncoding.DecodeString(x5cInterfaces[0].(string))
	if err != nil {
		logger.Warnf("The client cert could not be decoded. Token: %s", logging.PrettyPrintObject(token))
		return nil, err
	}
	clientCert, err := x509.ParseCertificate(decodedClientCert)
	if err != nil {
		logger.Warnf("The client cert could not be parsed. Token: %s", logging.PrettyPrintObject(token))
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
			if !th.trustedParticipantRepository.IsTrusted(parsedCert) {
				logger.Warnf("Only trusted CAs are accepted.")
				return nil, errors.New("untrusted_ca")
			} else {
				rootPool.AddCert(parsedCert)
			}
			continue
		}
		intermediatePool.AddCert(parsedCert)
	}

	logger.Tracef("Its now %v", th.Clock.Now())
	opts := x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: th.Clock.Now()}
	if _, err := clientCert.Verify(opts); err != nil {
		logger.Warnf("The cert could not be verified.")
		return nil, err
	}
	return clientCert.PublicKey.(*rsa.PublicKey), nil
}

func (tokenHandler *TokenHandler) GetTokenFromAR(authorizationRegistry *model.AuthorizationRegistry) (accessToken string, httpErr model.HttpError) {

	signedToken, err := tokenHandler.GenerateSignedToken(authorizationRegistry.Id, iShareClientId)
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

	logger.Debugf("Accessing ar %s with id %s and token %s", authorizationRegistry.GetTokenAddress(), iShareClientId, signedToken)

	// get the token
	tokenResponse, err := globalHttpClient.PostForm(authorizationRegistry.GetTokenAddress(), requestData)
	if err != nil {
		logger.Debugf("Failed to get token response from ar at: %s", authorizationRegistry.GetTokenAddress())
		return accessToken, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to get the token from the idp.", RootError: err}

	}

	if tokenResponse == nil || tokenResponse.StatusCode != 200 || tokenResponse.Body == nil {
		if tokenResponse != nil && tokenResponse.Body != nil {
			logger.Debugf("Response was %d - %s.", tokenResponse.StatusCode, tokenResponse.Body)
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

func (tokenHandler *TokenHandler) GenerateSignedToken(arId string, clientId string) (signedToken string, err error) {

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
	jwtToken.Header["x5c"] = tokenHandler.certificateArray

	defer func() {

		if panicErr := recover(); panicErr != nil {
			logger.Warnf("An invalid key was configured: %v. Err: %s", tokenHandler.signingKey, panicErr)
			err = errors.New("invalid_key_configured")
		}
	}()
	// sign the token
	signedToken, err = jwtToken.SignedString(tokenHandler.signingKey)
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

type TokenFunc func(*model.AuthorizationRegistry) (string, model.HttpError)
type TrustedListParseFunc func(string) (*model.TrustedListToken, model.HttpError)
