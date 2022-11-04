package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
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
		c.AbortWithStatus(401)
		return
	}
	token := getTokenFromBearer(authorizationHeader)

	originalAddress := c.GetHeader("X-Original-URI")
	requestType := c.GetHeader("X-Original-Action")

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Warn("Was not able to read the body, will set it to empty.", err)
		bodyData = []byte{}
	}

	var jsonData map[string]interface{}
	if err := json.Unmarshal(bodyData, &jsonData); err != nil {
		logger.Warn("Was not able to decode the body. Will not use it for the descision.", err)
	}

	decision, httpErr := decider.Decide(token, originalAddress, requestType, &jsonData)

	if httpErr != (httpError{}) {
		logger.Warnf("Did not receive a valid decision. Error: %v", httpErr.rootError)
		c.AbortWithError(httpErr.status, &httpErr)
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
