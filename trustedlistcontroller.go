package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
)

var issuerRepo IssuerRepository

func init() {
	dbEnabled, dbErr := strconv.ParseBool(os.Getenv("DB_ENABLED"))

	if dbErr != nil && dbEnabled {
		logger.Fatal("DB is not yet supported.")
		return
	}
	issuerRepo = InMemoryRepo{}
}

func createTrustedIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var trustedIssuer TrustedIssuer
	err = json.Unmarshal(bodyData, &trustedIssuer)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}
	httpErr := issuerRepo.CreateIssuer(trustedIssuer)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to create issuer %s.", prettyPrintObject(trustedIssuer))
		c.AbortWithStatusJSON(httpErr.status, ProblemDetails{Type: "RepositoryError", Status: httpErr.status, Title: "Failed to create issuer.", Detail: httpErr.message})
		return
	}
	c.AbortWithStatus(http.StatusCreated)
}

func replaceIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var trustedIssuer TrustedIssuer
	err = json.Unmarshal(bodyData, &trustedIssuer)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}
	httpErr := issuerRepo.PutIssuer(trustedIssuer)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to replace issuer %s.", prettyPrintObject(trustedIssuer))
		c.AbortWithStatusJSON(httpErr.status, ProblemDetails{Type: "RepositoryError", Status: httpErr.status, Title: "Failed to replace issuer.", Detail: httpErr.message})
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

func getIssuerById(c *gin.Context) {
	issuerId := c.Param("id")
	trustedIssuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (httpError{}) {
		c.AbortWithStatusJSON(httpErr.status, ProblemDetails{Type: "NotFound", Status: httpErr.status, Title: "Issuer not found.", Detail: httpErr.message})
		return
	}
	c.AbortWithStatusJSON(http.StatusOK, trustedIssuer)
}

func deleteIssuerById(c *gin.Context) {
	issuerId := c.Param("id")
	httpErr := issuerRepo.DeleteIssuer(issuerId)
	if httpErr != (httpError{}) {
		c.AbortWithStatusJSON(httpErr.status, ProblemDetails{Type: "NotFound", Status: httpErr.status, Title: "Issuer not found.", Detail: httpErr.message})
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

func getIssuers(c *gin.Context) {
	query := c.Request.URL.Query()
	limitParam := query.Get("limit")
	if limitParam == "" {
		limitParam = "100"
	}
	offsetParam := query.Get("offset")
	if offsetParam == "" {
		offsetParam = "0"
	}
	limit, err := strconv.Atoi(limitParam)
	if err != nil || limit < 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "InvalidParameter", Status: http.StatusBadRequest, Title: "Invalid query parameter", Detail: fmt.Sprintf("Limit is not a valid number: %s", limitParam)})
		return
	}
	offset, err := strconv.Atoi(limitParam)
	if err != nil || offset < 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, ProblemDetails{Type: "InvalidParameter", Status: http.StatusBadRequest, Title: "Invalid query parameter", Detail: fmt.Sprintf("Offset is not a valid number: %s", offsetParam)})
		return
	}

	trustedIssuers, httpErr := issuerRepo.GetIssuers(limit, offset)
	if httpErr != (httpError{}) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, ProblemDetails{Type: "RepositoryError", Status: http.StatusInternalServerError, Title: "Unable to get issuers from repo", Detail: httpErr.message})
	}
	c.AbortWithStatusJSON(http.StatusOK, trustedIssuers)
}
