package trustedissuer

import (
	"encoding/json"
	"io/ioutil"
	"net/http"
	"os"
	"strconv"

	"github.com/fiware/dsba-pdp/ishare"
	"github.com/fiware/dsba-pdp/model"
	"github.com/gin-gonic/gin"
)

var verifier IssuerVerifier

func init() {
	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_TRUSTED_LIST_ENABLED"))

	if ishareErr == nil && ishareEnabled {
		logger.Info("iShare is enabled.")
		// needs to be the iShare verifier
		verifier = NewAuthorizationRegistryVerifier(ishare.NewIShareAuthorizationRegistry(), envConfig)
	} else {
		verifier = &FiwareVerifier{}
	}
}

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
	decision, httpErr := verifier.Verify(verifiableCredential)
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
