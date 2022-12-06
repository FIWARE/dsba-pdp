package decision

import (
	"bytes"
	"context"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/procyon-projects/chrono"
	"github.com/wistefan/dsba-pdp/logging"
	"github.com/wistefan/dsba-pdp/model"
)

const FingerprintsListEnvVar = "ISHARE_TRUSTED_FINGERPRINTS_LIST"
const SatellitUrlEnvVar = "SATELLITE_URL"
const SatelliteIdEnvVar = "SATELLITE_ID"
const TrustedListUpdateRateEnvVar = "ISHARE_TRUSTED_LIST_UPDATE_RATE"

var satelliteURL = "https://scheme.isharetest.net"
var satelliteId = "EU.EORI.NL000000000"
var updateRateInS = 5

type TrustedParticipantRepository interface {
	IsTrusted(certificate *x509.Certificate) (isTrusted bool)
}

type IShareTrustedParticipantRepository struct {
	satelliteAr         *model.AuthorizationRegistry
	trustedFingerprints [][]byte
	tokenFunc           TokenFunc
	parserFunc          TrustedListParseFunc
}

func NewTrustedParticipantRepository(tokenFunc TokenFunc, parserFunc TrustedListParseFunc) *IShareTrustedParticipantRepository {

	trustedParticipantRepo := new(IShareTrustedParticipantRepository)

	fingerprintsString := os.Getenv(FingerprintsListEnvVar)
	if fingerprintsString == "" {
		logger.Fatal("No initial fingerprints configured for the satellite.")
		return nil
	}

	trustedFingerprints := [][]byte{}
	for _, fingerPrint := range strings.Split(fingerprintsString, ",") {
		trustedFingerprints = append(trustedFingerprints, []byte(fingerPrint))
	}

	trustedParticipantRepo.trustedFingerprints = trustedFingerprints

	logger.Debugf("Initially trusted fingerprints: %s.", trustedParticipantRepo.trustedFingerprints)

	satelliteUrlEnv := os.Getenv(SatellitUrlEnvVar)
	if satelliteUrlEnv != "" {
		satelliteURL = satelliteUrlEnv
	}
	satelliteIdEnv := os.Getenv(SatelliteIdEnvVar)
	if satelliteIdEnv != "" {
		satelliteId = satelliteIdEnv
	}

	updateRateInSEnv, err := strconv.Atoi(os.Getenv(TrustedListUpdateRateEnvVar))
	if err != nil {
		logger.Warnf("Invalid trustedlist update rate configured. Using the default %ds. Err: %s", updateRateInS, logging.PrettyPrintObject(err))
	} else if updateRateInSEnv > 0 {
		updateRateInS = updateRateInSEnv
	}
	ar := model.AuthorizationRegistry{Id: satelliteId, Host: satelliteURL}

	logger.Debugf("Using satellite %s as trust anchor.", logging.PrettyPrintObject(ar))
	trustedParticipantRepo.satelliteAr = &ar
	trustedParticipantRepo.tokenFunc = tokenFunc
	trustedParticipantRepo.parserFunc = parserFunc

	trustedParticipantRepo.scheduleTrustedListUpdate(updateRateInS)

	return trustedParticipantRepo
}

func (icr IShareTrustedParticipantRepository) scheduleTrustedListUpdate(updateRateInS int) {
	taskScheduler := chrono.NewDefaultTaskScheduler()
	taskScheduler.ScheduleAtFixedRate(icr.updateTrustedFingerprints, time.Duration(time.Duration(updateRateInS).Seconds()))
}

func (icr IShareTrustedParticipantRepository) IsTrusted(certificate *x509.Certificate) (isTrusted bool) {
	certificateFingerPrint := buildCertificateFingerprint(certificate)
	logger.Debugf("Checking certificate with fingerprint %s.", string(certificateFingerPrint))
	if contains(icr.trustedFingerprints, certificateFingerPrint) {
		logger.Debug("The presented certificate is trusted.")
		return true
	}
	return false
}

func (icr IShareTrustedParticipantRepository) updateTrustedFingerprints(ctx context.Context) {

	logger.Debugf("Certificate is not the satellite, request the current list.")
	trustedList, httpErr := icr.getTrustedList()
	if httpErr != (model.HttpError{}) {
		logger.Warnf("Was not able to get the trusted list. Err: %s", logging.PrettyPrintObject(httpErr))
		return
	}
	updatedFingerPrints := [][]byte{}
	for _, trustedParticipant := range *trustedList {

		if trustedParticipant.Validity != "valid" {
			logger.Debugf("The participant %s is not valid.", logging.PrettyPrintObject(trustedParticipant))
			continue
		}
		if trustedParticipant.Status != "granted" {
			logger.Debugf("The participant %s is not granted.", logging.PrettyPrintObject(trustedParticipant))
			continue
		}
		updatedFingerPrints = append(updatedFingerPrints, []byte(trustedParticipant.CertificateFingerprint))
	}
	icr.trustedFingerprints = updatedFingerPrints
	logger.Debugf("Updated trusted fingerprints to: %s", icr.trustedFingerprints)
}

func (icr IShareTrustedParticipantRepository) getTrustedList() (trustedList *[]model.TrustedParticipant, httpErr model.HttpError) {
	accessToken, httpErr := icr.tokenFunc(icr.satelliteAr)
	if httpErr != (model.HttpError{}) {
		logger.Debugf("Was not able to get a token from the satellite at %s.", logging.PrettyPrintObject(icr.satelliteAr))
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

func buildCertificateFingerprint(certificate *x509.Certificate) (fingerprint []byte) {
	logger.Debugf("Sum %s", sha256.New().Sum(certificate.Raw))
	logger.Debugf("Sum256 %s", sha256.Sum256(certificate.Raw))
	logger.Debugf("Sum224 %s", sha256.Sum224(certificate.Raw))
	logger.Debugf("Sum1 %s", sha1.Sum(certificate.Raw))

	fingerprintBytes := sha256.Sum256(certificate.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprintBytes {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	fmt.Printf("Fingerprint: %s\n", buf.String())

	return fingerprintBytes[:]
}

func contains(s [][]byte, e []byte) bool {
	for _, a := range s {
		if bytes.Equal(a, e) {
			return true
		}
	}
	return false
}
