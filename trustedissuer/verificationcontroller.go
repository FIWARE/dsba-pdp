package trustedissuer

import (
	"encoding/json"
	"io/ioutil"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/wistefan/dsba-pdp/model"
)

func VerifyIssuer(c *gin.Context) {

	bodyData, err := ioutil.ReadAll(c.Request.Body)
	if err != nil {
		logger.Debugf("Was not able to read the body, return error %v.", err)
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to read body", Detail: err.Error()})
		return
	}

	var verifiableCredential model.DSBAVerifiableCredential
	err = json.Unmarshal(bodyData, &verifiableCredential)
	if err != nil {
		logger.Debugf("Was not able to unmarshal request body: %s", string(bodyData))
		c.AbortWithStatusJSON(http.StatusBadRequest, model.ProblemDetails{Type: "BadRequest", Status: http.StatusBadRequest, Title: "Unable to unmarshal body.", Detail: err.Error()})
		return
	}
	decision, httpErr := Verify(verifiableCredential)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get a decision from the verification. Mgs: %v", httpErr)
		c.AbortWithStatusJSON(httpErr.Status, model.ProblemDetails{Type: "VerificationError", Status: httpErr.Status, Title: "Unable to get a decision.", Detail: httpErr.Message})
		return
	}
	if decision.Decision {
		c.AbortWithStatus(http.StatusNoContent)
		return
	}
	c.AbortWithStatusJSON(http.StatusForbidden, decision)
}
