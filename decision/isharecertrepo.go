package decision

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

const SatelliteFingerprintEnvVar = "SATELLITE_FINGERPRINT"
const SatellitUrlEnvVar = "SATELLITE_URL"
const SatelliteIdEnvVar = "SATELLITE_ID"

var satelliteURL = "https://scheme.isharetest.net"
var satelliteId = "EU.EORI.NL000000000"

type TrustedParticipantRepository interface {
	IsTrusted(certificate *x509.Certificate) (isTrusted bool, httpErr model.HttpError)
	GetTrustedList() (trustedList *[]model.TrustedParticipant, httpErr model.HttpError)
}

type IShareTrustedParticipantRepository struct {
	satelliteAr          *model.AuthorizationRegistry
	satelliteFingerprint string
	tokenFunc            TokenFunc
	parserFunc           TrustedListParseFunc
}

func NewTrustedParticipantRepository(tokenFunc TokenFunc, parserFunc TrustedListParseFunc) *IShareTrustedParticipantRepository {

	trustedParticipantRepo := new(IShareTrustedParticipantRepository)

	satelliteFingerprint := os.Getenv(SatelliteFingerprintEnvVar)
	if satelliteFingerprint == "" {
		logger.Fatal("No fingerprint configured for the sattelite.")
		return nil
	}
	trustedParticipantRepo.satelliteFingerprint = satelliteFingerprint

	satelliteUrlEnv := os.Getenv(SatellitUrlEnvVar)
	if satelliteUrlEnv != "" {
		satelliteURL = satelliteUrlEnv
	}
	satelliteIdEnv := os.Getenv(SatelliteIdEnvVar)
	if satelliteIdEnv != "" {
		satelliteId = satelliteIdEnv
	}
	ar := model.AuthorizationRegistry{Id: satelliteId, Host: satelliteURL}

	logger.Debugf("Using sattelite %s as trust anchor.", logging.PrettyPrintObject(ar))
	trustedParticipantRepo.satelliteAr = &ar
	trustedParticipantRepo.tokenFunc = tokenFunc
	trustedParticipantRepo.parserFunc = parserFunc

	return trustedParticipantRepo
}

func (icr IShareTrustedParticipantRepository) IsTrusted(certificate *x509.Certificate) (isTrusted bool, httpErr model.HttpError) {
	certificateFingerPrint := buildCertificateFingerprint(certificate)
	if certificateFingerPrint == icr.satelliteFingerprint {
		logger.Debug("The presented certificate is the pre-configured sattelite certificate.")
		return true, httpErr
	}
	logger.Debugf("Certificate is not the satellite, request the current list.")
	trustedList, httpErr := icr.GetTrustedList()
	if httpErr != (model.HttpError{}) {
		return false, httpErr
	}
	for _, trustedParticipant := range *trustedList {
		if trustedParticipant.CertificateFingerprint != certificateFingerPrint {
			continue
		}
		if trustedParticipant.Validity != "valid" {
			logger.Debugf("The participant %s is not valid.", logging.PrettyPrintObject(trustedParticipant))
			return false, httpErr
		}
		if trustedParticipant.Status != "granted" {
			logger.Debugf("The participant %s is not granted.", logging.PrettyPrintObject(trustedParticipant))
			return false, httpErr
		}
		return true, httpErr
	}
	return false, httpErr
}

func (icr IShareTrustedParticipantRepository) GetTrustedList() (trustedList *[]model.TrustedParticipant, httpErr model.HttpError) {
	accessToken, httpErr := icr.tokenFunc(icr.satelliteAr)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get a token from the sattelite at %s.", logging.PrettyPrintObject(icr.satelliteAr))
		return trustedList, httpErr
	}

	trustedListURL := icr.satelliteAr.Host + "/trusted_list"

	trustedListRequest, err := http.NewRequest("GET", trustedListURL, nil)
	if err != nil {
		logger.Debug("Was not able to create the trustedlist request.")
		return trustedList, model.HttpError{Status: http.StatusInternalServerError, Message: "Was not able to create the request to the trusted list.", RootError: err}
	}
	trustedListRequest.Header.Set("Authorization", "Bearer "+accessToken)
	trustedListResponse, err := globalHttpClient.Do(trustedListRequest)
	if err != nil || trustedListResponse == nil {
		logger.Warnf("Was not able to get the trusted list from the satellite at %s.", logging.PrettyPrintObject(icr.satelliteAr))
		return trustedList, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to retrieve the trusted list.", RootError: err}
	}
	if trustedListResponse.StatusCode != 200 {
		logger.Warnf("Was not able to get a trusted list. Status: %s, Message: %v", trustedListResponse.Status, trustedListResponse.Body)
		return trustedList, model.HttpError{Status: http.StatusBadGateway, Message: "Was not able to retrieve the trusted list."}
	}

	var trustedListResponseObject model.TrustedListResponse
	err = json.NewDecoder(trustedListResponse.Body).Decode(&trustedListResponseObject)
	if err != nil {
		logger.Debugf("Was not able to decode the response body. Error: %v", err)
		return trustedList, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Received an invalid body from the satellite: %s", trustedListResponse.Body), RootError: err}
	}
	parsedToken, httpErr := icr.parserFunc(trustedListResponseObject.TrustedListToken)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to decode the ar response. Error: %v", httpErr)
		return trustedList, httpErr
	}
	logger.Debugf("Trusted list response: %v", logging.PrettyPrintObject(parsedToken))
	return parsedToken.TrustedList, httpErr
}

func buildCertificateFingerprint(certificate *x509.Certificate) (sha256fingerprint string) {
	fingerprintBytes := sha256.Sum256(certificate.Raw)
	return string(fingerprintBytes[:])
}
