package main

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
)

func verifyIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var verifiableCredential DSBAVerifiableCredential
	err = json.Unmarshal(bodyData, &verifiableCredential)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}
	decision, httpErr := Verify(verifiableCredential)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to get a decision from the verification. Mgs: %v", httpErr)
		c.AbortWithStatusJSON(httpErr.status, ProblemDetails{Type: "VerificationError", Status: httpErr.status, Title: "Unable to get a decision.", Detail: httpErr.message})
		return
	}
	if decision.Decision {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, decision)
}
