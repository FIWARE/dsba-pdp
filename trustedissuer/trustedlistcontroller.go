package trustedissuer

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strconv"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/gin-gonic/gin"
)

func CreateTrustedIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var trustedIssuer model.TrustedIssuer
	err = json.Unmarshal(bodyData, &trustedIssuer)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}
	httpErr := issuerRepo.CreateIssuer(trustedIssuer)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to create issuer %s.", logging.PrettyPrintObject(trustedIssuer))
		c.AbortWithStatusJSON(httpErr.Status, model.ProblemDetails{Type: "RepositoryError", Status: httpErr.Status, Title: "Failed to create issuer.", Detail: httpErr.Message})
		return
	}
	c.AbortWithStatus(http.StatusCreated)
}

func ReplaceIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var trustedIssuer model.TrustedIssuer
	err = json.Unmarshal(bodyData, &trustedIssuer)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}

	issuerId := c.Param("id")
	if trustedIssuer.Id != issuerId {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Id cannot be updated."})
		return
	}

	httpErr := issuerRepo.PutIssuer(trustedIssuer)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to replace issuer %s.", logging.PrettyPrintObject(trustedIssuer))
		c.AbortWithStatusJSON(httpErr.Status, model.ProblemDetails{Type: "RepositoryError", Status: httpErr.Status, Title: "Failed to replace issuer.", Detail: httpErr.Message})
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

func GetIssuerById(c *gin.Context) {
	issuerId := c.Param("id")
	trustedIssuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (model.HttpError{}) {
		c.AbortWithStatusJSON(httpErr.Status, model.ProblemDetails{Type: "NotFound", Status: httpErr.Status, Title: "Issuer not found.", Detail: httpErr.Message})
		return
	}
	c.AbortWithStatusJSON(http.StatusOK, trustedIssuer)
}

func DeleteIssuerById(c *gin.Context) {
	issuerId := c.Param("id")
	httpErr := issuerRepo.DeleteIssuer(issuerId)
	if httpErr != (model.HttpError{}) {
		c.AbortWithStatusJSON(httpErr.Status, model.ProblemDetails{Type: "NotFound", Status: httpErr.Status, Title: "Issuer not found.", Detail: httpErr.Message})
		return
	}
	c.AbortWithStatus(http.StatusNoContent)
}

func GetIssuers(c *gin.Context) {
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
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "InvalidParameter", Status: http.StatusBadRequest, Title: "Invalid query parameter", Detail: fmt.Sprintf("Limit is not a valid number: %s", limitParam)})
		return
	}
	offset, err := strconv.Atoi(offsetParam)
	if err != nil || offset < 0 {
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "InvalidParameter", Status: http.StatusBadRequest, Title: "Invalid query parameter", Detail: fmt.Sprintf("Offset is not a valid number: %s", offsetParam)})
		return
	}

	trustedIssuers, httpErr := issuerRepo.GetIssuers(limit, offset)
	if httpErr != (model.HttpError{}) {
		c.AbortWithStatusJSON(http.StatusInternalServerError, model.ProblemDetails{Type: "RepositoryError", Status: http.StatusInternalServerError, Title: "Unable to get issuers from repo", Detail: httpErr.Message})
	}
	c.AbortWithStatusJSON(http.StatusOK, trustedIssuers)
}
