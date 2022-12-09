package main

import (
	"encoding/json"
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

var decider decision.Decider
var verifier trustedissuer.IssuerVerifier

func init() {
	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))
	ishareTrustedListEnabled, ishareTLErr := strconv.ParseBool(os.Getenv("ISHARE_TRUSTED_LIST_ENABLED"))

	if ishareErr == nil && ishareEnabled {
		logger.Info("iShare is enabled.")
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
	token := getTokenFromBearer(authorizationHeader)

	unverifiedToken, parts, err := jwt.NewParser().ParseUnverified(token, &model.DSBAToken{})
	if err != nil {
		logger.Warn("Was not able to parse the token.")
		c.AbortWithStatusJSON(http.StatusUnauthorized, err)
		return
	}

	logger.Debugf("The unverified token is %s", logging.PrettyPrintObject(unverifiedToken))
	parsedToken := unverifiedToken.Claims.(*model.DSBAToken)
	logger.Debugf("Received token %s, parts: %s", logging.PrettyPrintObject(parsedToken), logging.PrettyPrintObject(parts))

	originalAddress := c.GetHeader("X-Original-URI")
	requestType := c.GetHeader("X-Original-Action")

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

/**
* Removes the bearer prefix and returns the token
 */
func getTokenFromBearer(bearer string) (token string) {
	token = strings.ReplaceAll(bearer, "Bearer ", "")
	token = strings.ReplaceAll(token, "bearer ", "")
	return
}
