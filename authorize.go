package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"
	"github.com/wistefan/dsba-pdp/config"
	"github.com/wistefan/dsba-pdp/decision"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
	"github.com/wistefan/dsba-pdp/trustedissuer"
)

var decider decision.Decider

func init() {
	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))

	if ishareErr == nil && ishareEnabled {
		logger.Info("iShare is enabled.")
		decider = decision.NewIShareDecider(decision.NewIShareAuthorizationRegistry(), config.EnvConfig{})
	}
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
	decision, httpErr := trustedissuer.Verify(parsedToken.VerifiableCredential)
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
