package trustedissuer

import (
	"fmt"
	"net/http"
	"time"

	"github.com/fiware/dsba-pdp/decision"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
)

var clock decision.Clock = &decision.RealClock{}

type IssuerVerifier interface {
	Verify(claims *[]model.Claim, credentialSubject *model.CredentialSubject, issuerId string) (decision model.Decision, httpErr model.HttpError)
}

var iShareVerifier IssuerVerifier = IShareCustomerCredentialVerifier{}
var customerCredentialsVerifier IssuerVerifier = CustomerCredentialVerifier{}

func Verify(vc model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {
	issuerId := vc.Issuer
	if issuerId == "" {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("VC %s does not contain a valid issuer id.", logging.PrettyPrintObject(vc))}, httpErr
	}
	issuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to retrieve issuer from repo for VC %s.", logging.PrettyPrintObject(vc))
		return model.Decision{Decision: false, Reason: httpErr.Message}, httpErr
	}

	if issuer.Capabilities == nil {
		logger.Debugf("No capabilities configured for the issuer %s.", logging.PrettyPrintObject(issuer))
		return model.Decision{Decision: false, Reason: "No capabilities configured for the issuer"}, httpErr
	}

	for _, capability := range *issuer.Capabilities {
		logger.Debugf("Handle capability %s.", logging.PrettyPrintObject(capability))
		decision, httpErr = evaluateCapability(capability, vc)
		logger.Debugf("Decision was %s.", logging.PrettyPrintObject(decision))
		if httpErr == (model.HttpError{}) && decision.Decision {
			logger.Debugf("Issuer is trusted. VC %s accepted.", logging.PrettyPrintObject(vc))
			return decision, httpErr
		}
	}
	return model.Decision{Decision: false, Reason: "No allowing capability found."}, httpErr
}

func evaluateCapability(capability model.Capability, vc model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {

	logger.Debugf("Evaluates %s for capability %s.", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability))

	now := clock.Now()

	validFrom, err := time.Parse(time.RFC3339, capability.ValidFor.From)
	if err != nil {
		logger.Warn("Was not able to parse timestamp.")
		return decision, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to parse validFrom.", RootError: err}
	}
	validTo, err := time.Parse(time.RFC3339, capability.ValidFor.To)
	if err != nil {
		logger.Warn("Was not able to parse timestamp.")
		return decision, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to parse validTo.", RootError: err}
	}
	if now.Before(validFrom) || now.After(validTo) {
		logger.Debugf("VC %s is not active by %s. Its now %v", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability), now)
		return model.Decision{Decision: false, Reason: "Capabilitiy is not active."}, httpErr
	}

	if !contains(vc.Type, capability.CredentialsType) {
		logger.Debugf("VC type for %s is not allowed by %s.", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability))
		return model.Decision{Decision: false, Reason: "Capbability does not allow that type of credential."}, httpErr
	}

	if capability.CredentialsType == "CustomerCredential" {

		if isIShareVC(vc.CredentialSubject) {

			logger.Debugf("Verify ishare customer credential.")
			return iShareVerifier.Verify(capability.Claims, &vc.CredentialSubject, vc.Issuer)
		} else {
			logger.Debugf("Verify customer credential %s.", logging.PrettyPrintObject(vc.CredentialSubject))
			return customerCredentialsVerifier.Verify(capability.Claims, &vc.CredentialSubject, vc.Issuer)
		}
	} else {
		logger.Debugf("Type %s is not supported.", capability.CredentialsType)
	}
	logger.Debug("Successfully verified vc.")
	return model.Decision{Decision: true, Reason: "No special checks required for the given type of credential."}, httpErr
}

func isIShareVC(credentialSubject model.CredentialSubject) bool {
	if credentialSubject.IShareCredentialsSubject != nil {
		return true
	}
	for _, role := range credentialSubject.Roles {
		if role.Provider != "" {
			return true
		}
	}
	return false
}

func containsAll(s []string, e []string) bool {
	for _, a := range e {
		if !contains(s, a) {
			return false
		}
	}
	return true
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
