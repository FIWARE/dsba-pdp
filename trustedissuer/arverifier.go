package trustedissuer

import (
	"fmt"

	"github.com/fiware/dsba-pdp/config"
	"github.com/fiware/dsba-pdp/ishare"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
)

const VC_ISSUE_ACTION = "ISSUE"

type AuthorizationRegistryVerifier struct {
	authorizationRegistry *ishare.IShareAuthorizationRegistry
	envConfig             *config.Config
}

func NewAuthorizationRegistryVerifier(authorizationRegistry *ishare.IShareAuthorizationRegistry, config config.Config) *AuthorizationRegistryVerifier {
	verifier := new(AuthorizationRegistryVerifier)
	verifier.authorizationRegistry = authorizationRegistry
	verifier.envConfig = &config
	return verifier
}

func (arv *AuthorizationRegistryVerifier) Verify(vc model.DSBAVerifiableCredential) (decision model.Decision, httpErr model.HttpError) {

	logger.Debugf("Verify the VC %s at the iShare AR.", logging.PrettyPrintObject(vc))

	issuerId := vc.Issuer
	if issuerId == "" {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("VC %s does not contain a valid issuer id.", logging.PrettyPrintObject(vc))}, httpErr
	}

	vcTypes := vc.Type
	if len(vcTypes) < 1 {
		return model.Decision{Decision: false, Reason: fmt.Sprintf("VC %s does not contain any type.", logging.PrettyPrintObject(vc))}, httpErr
	}

	issuedRoles := []string{}
	for _, role := range vc.CredentialSubject.Roles {
		if role.Target == (*arv.envConfig).ProviderId() {
			issuedRoles = append(issuedRoles, role.Names...)
		}
	}

	policiesToCheck := []model.Policy{}
	for _, vcType := range vcTypes {
		policiesToCheck = append(policiesToCheck, buildVCPolicy(vcType, issuedRoles))
	}

	for _, policyToCheck := range policiesToCheck {
		logger.Debugf("Evaluating policy %s.", logging.PrettyPrintObject(policyToCheck))
		decision, httpErr = arv.evaluatePolicy(policyToCheck, (*arv.envConfig).ProviderId(), issuerId)
		if decision.Decision {
			logger.Debugf("Policy %s does permit the VC.", logging.PrettyPrintObject(policyToCheck))
			return decision, httpErr
		}
		logger.Debugf("Policy %s does not permit the VC.", logging.PrettyPrintObject(policyToCheck))
	}
	return decision, httpErr

}

func (arv *AuthorizationRegistryVerifier) evaluatePolicy(policy model.Policy, vcIssuer string, vcTarget string) (decision model.Decision, httpErr model.HttpError) {
	policyWrapper := []model.Policy{policy}
	delegationEvidence, httpErr := arv.authorizationRegistry.GetDelegationEvidence(vcIssuer, vcTarget, &policyWrapper, arv.authorizationRegistry.GetPDPRegistry())
	if httpErr != (model.HttpError{}) {
		logger.Infof("Was not able to get a delegation evidence from the the ar %s. Err: %s.", logging.PrettyPrintObject(arv.authorizationRegistry.GetPDPRegistry()), logging.PrettyPrintObject(&httpErr))
		return decision, httpErr
	}
	return ishare.CheckDelegationEvidence(delegationEvidence), httpErr
}

func buildVCPolicy(vcType string, alloweRoles []string) model.Policy {

	logger.Debugf("Build policy for type %s, with roles %s.", vcType, alloweRoles)

	resource := model.Resource{
		Type:        vcType,
		Identifiers: []string{"*"},
		Attributes:  alloweRoles,
	}
	policy := model.Policy{
		Target: &model.PolicyTarget{
			Resource: &resource,
			Actions:  []string{VC_ISSUE_ACTION},
		},
		Rules: []model.Rule{{Effect: "Permit"}},
	}
	return policy
}
