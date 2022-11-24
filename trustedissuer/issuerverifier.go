package trustedissuer

import (
	"fmt"
	"time"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

func Verify(vc model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {
	issuerId := vc.Issuer
	if issuerId == "" {
		return model.Decision{false, fmt.Sprintf("VC %s does not contain a valid issuer id.", logging.PrettyPrintObject(vc))}, httpErr
	}
	issuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to retrieve issuer from repo for VC %s.", logging.PrettyPrintObject(vc))
		return model.Decision{false, httpErr.Message}, httpErr
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
	return model.Decision{false, "No allowing capability found."}, httpErr
}

func evaluateCapability(capability model.Capability, vc model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {

	logger.Debugf("Evaluates %s for capability %s.", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability))

	now := time.Now()

	validFrom, err := time.Parse(time.RFC3339, capability.ValidFor.From)
	if err != nil {
		logger.Warn("Was not able to parse timestamp.")
	}
	validTo, err := time.Parse(time.RFC3339, capability.ValidFor.To)
	if err != nil {
		logger.Warn("Was not able to parse timestamp.")
	}
	if now.Before(validFrom) || now.After(validTo) {
		logger.Debugf("VC %s is not active by %s.", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability))
		return model.Decision{false, "Capabilitiy is not active."}, httpErr
	}

	if !contains(vc.Type, capability.CredentialsType) {
		logger.Debugf("VC type for %s is not allowed by %s.", logging.PrettyPrintObject(vc), logging.PrettyPrintObject(capability))
		return model.Decision{false, "Capbability does not allow that type of credential."}, httpErr
	}

	if capability.CredentialsType == "CustomerCredential" {

		if isIShareVC(vc.CredentialSubject) {

			logger.Debugf("Verify ishare customer credential.")
			return IShareCustomerCredentialVerifier{}.Verify(capability.Claims, &vc.CredentialSubject, vc.Issuer)
		} else {
			logger.Debugf("Verify customer credential %s.", logging.PrettyPrintObject(vc.CredentialSubject))
			return CustomerCredentialVerifier{}.Verify(capability.Claims, &vc.CredentialSubject)
		}
	} else {
		logger.Debugf("Type %s is not supported.", capability.CredentialsType)
	}
	logger.Debug("Successfully verified vc.")
	return model.Decision{true, "No special checks required for the given type of credential."}, httpErr
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

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
