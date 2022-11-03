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
	if err := json.Unmarshal(bodyData, jsonData); err != nil {
		logger.Warn("Was not able to decode the body. Will not use it for the descision.", err)
	}

	decision, httpErr := decider.Decide(token, originalAddress, requestType, &jsonData)

	if httpErr != (httpError{}) {
		logger.Warn("Did not receive a valid decision. Error: %v", httpErr.rootError)
		c.AbortWithError(httpErr.status, &httpErr)
		return
	}
	if decision.decision {
		logger.Debug("Successfully authorized request.")
		c.Status(http.StatusOK)
		return
	}
	logger.Debug("Denied the request because of: %s", decision.reason)
	decisionJson, _ := json.Marshal(decision)

	c.AbortWithStatusJSON(http.StatusForbidden, decisionJson)
}

/**
* Removes the bearer prefix and returns the token
 */
func getTokenFromBearer(bearer string) (token string) {
	strings.ReplaceAll("Bearer ", bearer, token)
	strings.ReplaceAll("bearer ", bearer, token)
	return
}

// interface of the configured decider

type Decider interface {
	Decide(token string, originalAddress string, requestType string, requestBody *map[string]interface{}) (descision Decision, err httpError)
}

// error interface

type Decision struct {
	decision bool   `json:"decision`
	reason   string `json:"reason"`
}

type httpError struct {
	status    int
	message   string
	rootError error
}

func (err *httpError) Error() string {
	return err.message
}

func (err *httpError) GetRoot() error {
	return err.rootError
}
