package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/fiware/dsba-pdp/config"
	"github.com/fiware/dsba-pdp/decision"
	"github.com/fiware/dsba-pdp/ishare"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/fiware/dsba-pdp/trustedissuer"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
)

const originalAddressHeader = "X-Original-URI"
const originalActionHeader = "X-Original-Action"

var decider decision.Decider
var verifier trustedissuer.IssuerVerifier
var verifierRepository *VerifierRepository

func init() {
	logger.Debug("Initalize authorize.")

	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))
	ishareTrustedListEnabled, ishareTLErr := strconv.ParseBool(os.Getenv("ISHARE_TRUSTED_LIST_ENABLED"))

	verifierRepository = NewVerifierRepository()
	if ishareErr == nil && ishareEnabled {
		logger.Info("iShare decider is enabled.")
		decider = ishare.NewIShareDecider(ishare.NewIShareAuthorizationRegistry(), config.EnvConfig{})
	}
	if ishareTLErr == nil && ishareTrustedListEnabled {
		logger.Info("Trustedlist based on the iShare AR is enabled. With this configuration, everything inside the internal trustedlist will be ignored.")
		verifier = trustedissuer.NewAuthorizationRegistryVerifier(ishare.NewIShareAuthorizationRegistry(), config.EnvConfig{})
	} else {
		logger.Info("Use the FIWARE Verifier, based on the internal trusted list.")
		verifier = &trustedissuer.FiwareVerifier{}
	}
	logger.Debugf("Ishare verifier enabled: %v, err: %v ", ishareTrustedListEnabled, ishareTLErr)

}

func authorize(c *gin.Context) {

	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		logger.Warn("No authorization header was provided, will skip decision.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	logger.Debugf("Received the token %s to authorize.", authorizationHeader)
	tokenString := getTokenFromBearer(authorizationHeader)

	token, err := jwt.ParseWithClaims(tokenString, &model.DSBAToken{}, func(t *jwt.Token) (interface{}, error) {
		logger.Debugf("Token alg %s, %v", t.Method.Alg(), jwt.GetSigningMethod(t.Method.Alg()))
		return getKeyFromToken(t)
	})

	if err != nil {
		logger.Warnf("Was not able to parse the token. Err: %s", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, err)
		return
	}

	logger.Debugf("The unverified token is %s", logging.PrettyPrintObject(token))

	parsedToken := token.Claims.(*model.DSBAToken)
	logger.Debugf("Received token %s.", logging.PrettyPrintObject(parsedToken))

	originalAddress := c.GetHeader(originalAddressHeader)
	requestType := c.GetHeader(originalActionHeader)

	logger.Debugf("Received request %s - %s.", requestType, originalAddress)

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Warn("Was not able to read the body, will set it to empty.", err)
		bodyData = []byte{}
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(bodyData, &jsonData); err != nil {
		logger.Warn("Was not able to decode the body. Will not use it for the descision.", err)
	}
	// verify trust in the issuer
	decision, httpErr := verifier.Verify(parsedToken.VerifiableCredential)
	if httpErr != (model.HttpError{}) {
		logger.Warnf("Did not receive a valid decision from the trusted issuer verfication. Error: %v - root: %v", httpErr, httpErr.RootError)
		c.AbortWithStatusJSON(httpErr.Status, httpErr)
		return
	}
	if !decision.Decision {
		logger.Debugf("Trusted issuer verficiation failed, because of: %s", decision.Reason)
		c.AbortWithStatusJSON(http.StatusForbidden, decision)
		return
	}

	// evaluate and decide policies
	decision, httpErr = decider.Decide(parsedToken, originalAddress, requestType, &jsonData)

	if httpErr != (model.HttpError{}) {
		logger.Warnf("Did not receive a valid decision from the pdp. Error: %v - root: %v", httpErr, httpErr.RootError)
		c.AbortWithStatusJSON(httpErr.Status, httpErr)
		return
	}
	if decision.Decision {
		logger.Debug("Successfully authorized request.")
		c.Status(http.StatusOK)
		return
	}
	logger.Debugf("Denied the request because of: %s", decision.Reason)

	c.AbortWithStatusJSON(http.StatusForbidden, decision)
}

func getKeyFromToken(token *jwt.Token) (key interface{}, err error) {
	kid, ok := token.Header["kid"]
	if !ok {
		logger.Warn("Received a token without a kid header.")
		logger.Debugf("The token was: %s", token.Raw)
		return key, errors.New("no_kid_header_present")
	}
	jwk, err := verifierRepository.GetKey(kid.(string))
	if err != nil {
		return key, err
	}

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err = jwk.Raw(&rawkey); err != nil {
		logger.Warnf("failed to create public key: %s", err)
		return key, err
	}
	switch typedKey := rawkey.(type) {
	case *rsa.PublicKey:
		return typedKey, err
	case *ecdsa.PrivateKey:
		return &typedKey.PublicKey, err
	default:
		return key, errors.New("invalid_key_type")
	}
}

/**
* Removes the bearer prefix and returns the token
 */
func getTokenFromBearer(bearer string) (token string) {
	token = strings.ReplaceAll(bearer, "Bearer ", "")
	token = strings.ReplaceAll(token, "bearer ", "")
	return
}
