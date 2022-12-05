package decision

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"

	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

const FingerprintsListEnvVar = "TRUSTED_FINGERPRINTS_LIST"
const SatellitUrlEnvVar = "SATELLITE_URL"
const SatelliteIdEnvVar = "SATELLITE_ID"

var satelliteURL = "https://scheme.isharetest.net"
var satelliteId = "EU.EORI.NL000000000"

type TrustedParticipantRepository interface {
	IsTrusted(certificate *x509.Certificate) (isTrusted bool)
	GetTrustedList() (trustedList *[]model.TrustedParticipant, httpErr model.HttpError)
}

type IShareTrustedParticipantRepository struct {
	satelliteAr         *model.AuthorizationRegistry
	trustedFingerprints []string
	tokenFunc           TokenFunc
	parserFunc          TrustedListParseFunc
}

func NewTrustedParticipantRepository(tokenFunc TokenFunc, parserFunc TrustedListParseFunc) *IShareTrustedParticipantRepository {

	trustedParticipantRepo := new(IShareTrustedParticipantRepository)

	fingerprintsString := os.Getenv(FingerprintsListEnvVar)
	if fingerprintsString == "" {
		logger.Fatal("No initial fingerprints configured for the sattelite.")
		return nil
	}

	trustedParticipantRepo.trustedFingerprints = strings.Split(fingerprintsString, ",")

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

func (icr IShareTrustedParticipantRepository) IsTrusted(certificate *x509.Certificate) (isTrusted bool) {
	certificateFingerPrint := buildCertificateFingerprint(certificate)
	if contains(icr.trustedFingerprints, certificateFingerPrint) {
		logger.Debug("The presented certificate is the pre-configured sattelite certificate.")
		return true
	}
	logger.Debugf("Certificate is not the satellite, request the current list.")
	trustedList, httpErr := icr.GetTrustedList()
	if httpErr != (model.HttpError{}) {
		logger.Warnf("Was not able to get the trusted list. Err: %s", logging.PrettyPrintObject(httpErr))
		return false
	}
	for _, trustedParticipant := range *trustedList {
		if trustedParticipant.CertificateFingerprint != certificateFingerPrint {
			continue
		}
		if trustedParticipant.Validity != "valid" {
			logger.Debugf("The participant %s is not valid.", logging.PrettyPrintObject(trustedParticipant))
			return false
		}
		if trustedParticipant.Status != "granted" {
			logger.Debugf("The participant %s is not granted.", logging.PrettyPrintObject(trustedParticipant))
			return false
		}
		return true
	}
	return false
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

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
