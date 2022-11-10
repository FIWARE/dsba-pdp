package main

import (
	"fmt"
	"time"
)

type CustomerCredentialSubject struct {
	Id    string   `json:"id"`
	Roles []string `json:"roles"`
}

func Verify(vc DSBAVerifiableCredential) (decision Decision, httpErr httpError) {
	issuerId := vc.Issuer.Id
	if issuerId == "" {
		return Decision{false, fmt.Sprintf("VC %s does not contain a valid issuer id.", prettyPrintObject(vc))}, httpErr
	}
	issuer, httpErr := issuerRepo.GetIssuer(issuerId)
	if httpErr != (httpError{}) {
		logger.Debugf("Was not able to retrieve issuer from repo for VC %s.", prettyPrintObject(vc))
		return Decision{false, httpErr.message}, httpErr
	}
	for _, capability := range *issuer.Capabilities {
		decision, httpErr = evaluateCapability(capability, vc)
		if httpErr == (httpError{}) && decision.Decision {
			logger.Debugf("Issuer is trusted. VC %s accepted.", prettyPrintObject(vc))
			return decision, httpErr
		}
	}
	return Decision{false, "Not allowing capability found."}, httpErr
}

func evaluateCapability(capability Capability, vc DSBAVerifiableCredential) (decision Decision, httpErr httpError) {

	now := time.Now()

	validFrom, _ := time.Parse(time.RFC3339, capability.ValidFor.From)
	validTo, _ := time.Parse(time.RFC3339, capability.ValidFor.To)
	if now.Before(validFrom) || now.After(validTo) {
		logger.Debugf("VC %s is not active by %s.", prettyPrintObject(vc), prettyPrintObject(capability))
		return Decision{false, "Capabilitiy is not active."}, httpErr
	}

	if !contains(vc.Type, capability.CredentialsType) {
		logger.Debugf("VC type for %s is not allowed by %s.", prettyPrintObject(vc), prettyPrintObject(capability))
		return Decision{false, "Capbability does not allow that type of credential."}, httpErr
	}

	if capability.CredentialsType == "CustomerCredential" {
		credentialsSubject, ok := vc.CredentialSubject.(*CustomerCredentialSubject)
		if !ok {
			return Decision{false, "CredentialSubject is not of the expected format for type CustomerCredential."}, httpErr
		}
		return CustomerCredentialVerifier{}.Verify(capability.Claims, credentialsSubject)
	} else if capability.CredentialsType == "IShareCustomerCredential" {

		// not properly implemented yet
		credentialsSubject, ok := vc.CredentialSubject.(*CustomerCredentialSubject)
		if !ok {
			return Decision{false, "CredentialSubject is not of the expected format for type CustomerCredential."}, httpErr
		}
		return CustomerCredentialVerifier{}.Verify(capability.Claims, credentialsSubject)
	}
	return Decision{true, "No special checks required for the given type of credential."}, httpErr
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
