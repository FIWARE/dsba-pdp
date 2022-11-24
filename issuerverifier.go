package main

import (
	"fmt"
	"os"
	"time"
)

var ProviderId string

func init() {
	ProviderId = os.Getenv("PROVIDER_ID")
	if ProviderId == "" {
		logger.Fatalf("No provider id configured, cannot verify credentials.")
	}
}

func Verify(vc DSBAVerifiableCredential) (decision Decision, httpErr httpError) {
	issuerId := vc.Issuer
	if issuerId == "" {
		return Decision{false, fmt.Sprintf("VC %s does not contain a valid issuer id.", prettyPrintObject(vc))}, httpErr
	}
	issuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to retrieve issuer from repo for VC %s.", prettyPrintObject(vc))
		return Decision{false, httpErr.message}, httpErr
	}
	for _, capability := range *issuer.Capabilities {
		logger.Debugf("Handle capability %s.", prettyPrintObject(capability))
		decision, httpErr = evaluateCapability(capability, vc)
		logger.Debugf("Decision was %s.", prettyPrintObject(decision))
		if httpErr == (httpError{}) && decision.Decision {
			logger.Debugf("Issuer is trusted. VC %s accepted.", prettyPrintObject(vc))
			return decision, httpErr
		}
	}
	return Decision{false, "No allowing capability found."}, httpErr
}

func evaluateCapability(capability Capability, vc DSBAVerifiableCredential) (decision Decision, httpErr httpError) {

	logger.Debugf("Evaluates %s for capability %s.", prettyPrintObject(vc), prettyPrintObject(capability))

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
		logger.Debugf("VC %s is not active by %s.", prettyPrintObject(vc), prettyPrintObject(capability))
		return Decision{false, "Capabilitiy is not active."}, httpErr
	}

	if !contains(vc.Type, capability.CredentialsType) {
		logger.Debugf("VC type for %s is not allowed by %s.", prettyPrintObject(vc), prettyPrintObject(capability))
		return Decision{false, "Capbability does not allow that type of credential."}, httpErr
	}

	if capability.CredentialsType == "CustomerCredential" {

		if isIShareVC(vc.CredentialSubject) {

			logger.Debugf("Verify ishare customer credential.")
			return IShareCustomerCredentialVerifier{}.Verify(capability.Claims, &vc.CredentialSubject, vc.Issuer)
		} else {
			logger.Debugf("Verify customer credential", prettyPrintObject(vc.CredentialSubject))
			return CustomerCredentialVerifier{}.Verify(capability.Claims, &vc.CredentialSubject)
		}
	} else {
		logger.Debugf("Type %s is not supported.", capability.CredentialsType)
	}
	logger.Debug("Successfully verified vc.")
	return Decision{true, "No special checks required for the given type of credential."}, httpErr
}

func isIShareVC(credentialSubject CredentialSubject) bool {
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
