package main

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/json"
	"errors"
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

const originalAddressHeader = "X-Original-URI"
const originalActionHeader = "X-Original-Action"

var decider decision.Decider
var verifier trustedissuer.IssuerVerifier
var verifierRepository *VerifierRepository

func init() {
	logger.Debug("Initalize authorize.")

	ishareEnabled, ishareErr := strconv.ParseBool(os.Getenv("ISHARE_ENABLED"))
	ishareTrustedListEnabled, ishareTLErr := strconv.ParseBool(os.Getenv("ISHARE_TRUSTED_LIST_ENABLED"))

	verifierRepository = NewVerifierRepository()
	if ishareErr == nil && ishareEnabled {
		logger.Info("iShare decider is enabled.")
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

func verifyDSBACredential(c *gin.Context, dsbaCredential *model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {

	originalAddress := c.GetHeader(originalAddressHeader)
	requestType := c.GetHeader(originalActionHeader)

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
	decision, httpErr = verifier.Verify(*dsbaCredential)
	if httpErr != (model.HttpError{}) {
		logger.Warnf("Did not receive a valid decision from the trusted issuer verfication. Error: %v - root: %v", httpErr, httpErr.RootError)
		return decision, httpErr
	}
	if !decision.Decision {
		logger.Debugf("Trusted issuer verficiation failed, because of: %s", decision.Reason)
		return decision, httpErr
	}

	// evaluate and decide policies
	decision, httpErr = decider.Decide(dsbaCredential, originalAddress, requestType, &jsonData)

	if httpErr != (model.HttpError{}) {
		logger.Warnf("Did not receive a valid decision from the pdp. Error: %v - root: %v", httpErr, httpErr.RootError)
		return decision, httpErr
	}
	return decision, httpErr
}

func authorize(c *gin.Context) {

	authorizationHeader := c.GetHeader("Authorization")
	if authorizationHeader == "" {
		logger.Warn("No authorization header was provided, will skip decision.")
		c.AbortWithStatus(http.StatusUnauthorized)
		return
	}
	logger.Debugf("Received the token %s to authorize.", authorizationHeader)
	tokenString := getTokenFromBearer(authorizationHeader)

	dsbaToken, err := jwt.ParseWithClaims(tokenString, &model.DSBAToken{}, func(t *jwt.Token) (interface{}, error) {
		logger.Debugf("Token alg %s, %v", t.Method.Alg(), jwt.GetSigningMethod(t.Method.Alg()))
		return getKeyFromToken(t)
	})

	// dsba token received, normal decision flow
	if dsbaToken.Claims.(*model.DSBAToken).VerifiableCredential != nil {

		logger.Debugf("The unverified token is %s", logging.PrettyPrintObject(dsbaToken))

		decision, httpErr := verifyDSBACredential(c, dsbaToken.Claims.(*model.DSBAToken).VerifiableCredential)
		if httpErr != (model.HttpError{}) {
			c.AbortWithStatusJSON(httpErr.Status, httpErr)
			return
		}
		if !decision.Decision {
			c.AbortWithStatusJSON(http.StatusForbidden, decision)
			return
		}
		logger.Debug("Successfully authorized request.")
		c.Status(http.StatusOK)
		return
	}

	gaiaXToken, err := jwt.ParseWithClaims(tokenString, &model.GaiaXToken{}, func(t *jwt.Token) (interface{}, error) {
		logger.Debugf("Token alg %s, %v", t.Method.Alg(), jwt.GetSigningMethod(t.Method.Alg()))
		return getKeyFromToken(t)
	})

	if err != nil {
		logger.Warnf("Was not able to parse the token. Err: %s", err)
		c.AbortWithStatusJSON(http.StatusUnauthorized, err)
		return
	}

	decision, httpErr := verifyGaiaXToken(c, gaiaXToken.Claims.(*model.GaiaXToken))
	if httpErr != (model.HttpError{}) {
		c.AbortWithStatusJSON(httpErr.Status, httpErr)
		return
	}
	if decision.Decision {
		logger.Debug("Successfully authorized request.")
		c.Status(http.StatusOK)
	}
	logger.Infof("Request was not allowed - Reason: %s", decision.Reason)
	c.AbortWithStatusJSON(http.StatusForbidden, decision)
}

func verifyGaiaXToken(c *gin.Context, gaiaXToken *model.GaiaXToken) (decision model.Decision, httpErr model.HttpError) {

	var userCredential *model.DSBAVerifiableCredential
	var participantCredential *model.DSBAVerifiableCredential

	for _, vc := range gaiaXToken.VerifiablePresentation {
		logger.Infof("Start to handle vc %s", logging.PrettyPrintObject(vc))
		vcString, _ := json.Marshal(vc)
		var theCredential model.DSBAVerifiableCredential
		json.Unmarshal(vcString, &theCredential)
		subject := theCredential.CredentialSubject
		if subject.IShareCredentialsSubject != nil {
			userCredential = &theCredential
			continue
		}
		if subject.GaiaXSubject != nil && subject.GaiaXSubject.Type == "gx:LegalParticipant" {
			participantCredential = &theCredential
			continue
		}
	}
	if userCredential == nil || participantCredential == nil {
		logger.Warnf("A valid token needs to contain a user credential and a participant credential. Was user: %v, participant: %v", userCredential, participantCredential)
		return decision, model.HttpError{Status: http.StatusForbidden, Message: "A valid token needs to contain a user credential and a participant credential."}
	}
	if userCredential.Issuer != participantCredential.CredentialSubject.Id {
		logger.Warn("The user credential was not issued by the participant.")
		logger.Debugf("UserCredential: %s, Participant: %s", logging.PrettyPrintObject(userCredential), logging.PrettyPrintObject(participantCredential))
		return model.Decision{Decision: false, Reason: "UserCredential was not issued by the participant."}, httpErr
	}
	return verifyDSBACredential(c, userCredential)
}

func getKeyFromToken(token *jwt.Token) (key interface{}, err error) {
	kid, ok := token.Header["kid"]
	if !ok {
		logger.Warn("Received a token without a kid header.")
		logger.Debugf("The token was: %s", token.Raw)
		return key, errors.New("no_kid_header_present")
	}
	jwk, err := verifierRepository.GetKey(kid.(string))
	if err != nil {
		return key, err
	}

	var rawkey interface{} // This is the raw key, like *rsa.PrivateKey or *ecdsa.PrivateKey
	if err = jwk.Raw(&rawkey); err != nil {
		logger.Warnf("failed to create public key: %s", err)
		return key, err
	}
	switch typedKey := rawkey.(type) {
	case *rsa.PublicKey:
		return typedKey, err
	case *ecdsa.PrivateKey:
		return &typedKey.PublicKey, err
	case *ecdsa.PublicKey:
		return typedKey, err
	default:
		logger.Warnf("Key type is %s.", logging.PrettyPrintObject(typedKey))
		return key, errors.New("invalid_key_type")
	}
}

/**
* Removes the bearer prefix and returns the token
 */
func getTokenFromBearer(bearer string) (token string) {
	token = strings.ReplaceAll(bearer, "Bearer ", "")
	token = strings.ReplaceAll(token, "bearer ", "")
	return
}
