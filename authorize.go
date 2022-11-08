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
)

var decider Decider

func init() {
	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))

	if ishareErr == nil || !ishareEnabled {
		logger.Info("iShare is enabled.")
		decider = iShareDecider{}
		return
	}
}

func authorize(c *gin.Context) {

	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		logger.Warn("No authorization header was provided, will skip decision.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	token := getTokenFromBearer(authorizationHeader)

	unverifiedToken, _, err := jwt.NewParser().ParseUnverified(token, &DSBAToken{})
	if err != nil {
		logger.Warn("Was not able to parse the token.")
		c.AbortWithStatusJSON(http.StatusUnauthorized, err)
		return
	}
	parsedToken := unverifiedToken.Claims.(*DSBAToken)
	logger.Debugf("Received token %s", prettyPrintObject(parsedToken))

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
	decision, httpErr := decider.Decide(parsedToken, originalAddress, requestType, &jsonData)

	if httpErr != (httpError{}) {
		logger.Warnf("Did not receive a valid decision. Error: %v - root: %v", httpErr, httpErr.rootError)
		c.AbortWithStatusJSON(httpErr.status, httpErr)
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

/**
* Helper method to print objects with json-serialization information in a more human readable way
 */
func prettyPrintObject(objectInterface interface{}) string {
	jsonBytes, err := json.Marshal(objectInterface)
	if err != nil {
		logger.Debugf("Was not able to pretty print the object: %v", objectInterface)
		return ""
	}
	return string(jsonBytes)
}
