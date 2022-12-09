package decision

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/model"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
)

type mockTrustedParticipantRepo struct {
	isTrusted bool
}

func (mtpr *mockTrustedParticipantRepo) IsTrusted(certificate *x509.Certificate) (isTrusted bool) {
	return mtpr.isTrusted
}

func (mtpr *mockTrustedParticipantRepo) GetTrustedList() (trustedList *[]model.TrustedParticipant, httpErr model.HttpError) {
	// not needed in the test
	return trustedList, httpErr
}

type mockFileAccessor struct {
	mockFile  map[string][]byte
	mockError map[string]error
}

func (mfa *mockFileAccessor) ReadFile(filename string) ([]byte, error) {
	return mfa.mockFile[filename], mfa.mockError[filename]
}

type mockHttpClient struct {
	mockDoResponse map[string]*http.Response
	mockPost       map[string]*http.Response
	mockError      map[string]error
}

func (mhc *mockHttpClient) Do(req *http.Request) (*http.Response, error) {
	address := req.URL.Scheme + "://" + req.URL.Host + req.URL.Path
	return mhc.mockDoResponse[address], mhc.mockError[address]
}

func (mhc *mockHttpClient) PostForm(url string, data url.Values) (*http.Response, error) {
	return mhc.mockDoResponse[url], mhc.mockError[url]
}

func getIShareTestRegistry(key *rsa.PrivateKey, certificates []string, isTrusted bool) *IShareAuthorizationRegistry {
	trustedParticipantRepo := &mockTrustedParticipantRepo{isTrusted: isTrusted}
	tokenHandler := &TokenHandler{trustedParticipantRepository: trustedParticipantRepo, signingKey: key, certificateArray: certificates, Clock: &mockClock{}}
	registry := IShareAuthorizationRegistry{pdpRegistry: getDefaultTestAR(), tokenHandler: tokenHandler}
	return &registry
}

func getDefaultTestAR() model.AuthorizationRegistry {
	return model.AuthorizationRegistry{Id: "myRegistry", Host: "http://fiware.org"}
}

func getTestKey() *rsa.PrivateKey {
	key, _ := getSigningKey("../examples/key.pem")
	return key
}

func getTestCerts() []string {
	certs, _ := getCertificateArray("../examples/cert.pem")
	return certs
}

func TestGetDelegationEvidence(t *testing.T) {
	// run tests verbose
	logging.Log().SetLevel(logrus.DebugLevel)

	type test struct {
		testName         string
		testRegistry     model.AuthorizationRegistry
		testKey          *rsa.PrivateKey
		testCertificates []string
		mockDoResponse   map[string]*http.Response
		mockPost         map[string]*http.Response
		mockError        map[string]error
		mockTrustCa      bool
		expectedEvidence *model.DelegationEvidence
		expectedError    model.HttpError
	}

	tests := []test{
		// bad requests
		{"If invalid private key is configured, an internal error should be returned.", getDefaultTestAR(), &rsa.PrivateKey{}, getTestCerts(), map[string]*http.Response{}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusInternalServerError}},

		// token endpoint errors
		{"If AR's token endpoint is unresponsive, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's token endpoint request throws an error, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{}, map[string]*http.Response{}, map[string]error{"http://fiware.org/connect/token": errors.New("request_timeout")}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If token isn't accepted, a BadGateway should be returned.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": forbiddenResponse()}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If token response contains an unparsable body, a BadGateway should be returned.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": {StatusCode: 200, Body: io.NopCloser(strings.NewReader("something_unexpected"))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If token response contains a body without an access token, a BadGateway should be returned.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": {StatusCode: 200, Body: io.NopCloser(strings.NewReader("{\"something\": \"unexpected\"}"))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},

		// delegation endpoint errors
		{"If AR's delegation endpoint is unresponsive, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse()}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation endpoint request throws an error, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse()}, map[string]*http.Response{}, map[string]error{"http://fiware.org/delegation": errors.New("request_timeout")}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation endpoint responds unexpected, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": forbiddenResponse()}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation endpoint responds 404, return a Forbidden.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": notFoundResponse()}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusForbidden}},
		{"If AR's delegation response contains no body, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains an unparsable body, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader("something_unexpected"))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains a body with the wrong format, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader("{\"something\": \"unexpected\"}"))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains a body with an non-jwt delegation_token, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader(nonJwtDelegationToken()))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains a body with an invalid delegation_token, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader(invalidDelegationToken()))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains a body with an invalid chain in the delegation_token, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader(invalidChainDelegationToken()))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},
		{"If AR's delegation response contains a body with an expired delegation_token, return a BadGateway.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader(expiredDelegationToken()))}}, map[string]*http.Response{}, map[string]error{}, true, nil, model.HttpError{Status: http.StatusBadGateway}},

		// valid request & return
		{"If a valid token is returned, the evidence from the token should be returned.", getDefaultTestAR(), getTestKey(), getTestCerts(), map[string]*http.Response{"http://fiware.org/connect/token": tokenResponse(), "http://fiware.org/delegation": {StatusCode: 200, Body: io.NopCloser(strings.NewReader(validDelegationToken()))}}, map[string]*http.Response{}, map[string]error{}, true, evidenceFromToken(), model.HttpError{}},
	}

	for _, tc := range tests {

		logger.Infof("TestGetDelegationEvidence +++++++++++++++++ Running test: %s", tc.testName)
		globalHttpClient = &mockHttpClient{tc.mockDoResponse, tc.mockPost, tc.mockError}
		registry := getIShareTestRegistry(tc.testKey, tc.testCertificates, tc.mockTrustCa)
		delegationEvidence, httpErr := registry.GetDelegationEvidence("myIssuer", "myTarget", &[]model.Policy{}, &tc.testRegistry)

		if httpErr.Status != tc.expectedError.Status {
			t.Errorf("%s: Unexpected error. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedError), logging.PrettyPrintObject(httpErr))
		}
		if (delegationEvidence == nil && tc.expectedEvidence != nil) || (delegationEvidence != nil && tc.expectedEvidence == nil) {
			t.Errorf("%s: Unexpected evidence. Expected: %v, Actual: %v", tc.testName, tc.expectedEvidence, delegationEvidence)
		}
		if delegationEvidence == nil && tc.expectedEvidence == nil {
			continue
		}
		logger.Debugf("%v and %v", delegationEvidence, tc.expectedEvidence)
		stringEvidence := logging.PrettyPrintObject(*delegationEvidence)
		stringExpectedEvidence := logging.PrettyPrintObject(*tc.expectedEvidence)
		if stringEvidence != stringExpectedEvidence {
			t.Errorf("%s: Unexpected evidence. Expected: %s, Actual: %s", tc.testName, stringExpectedEvidence, stringEvidence)
		}
	}
}

func TestGetSigningKeyErrors(t *testing.T) {

	logging.Log().SetLevel(logrus.DebugLevel)

	type test struct {
		testName      string
		testKey       []byte
		mockError     error
		expectedError error
	}

	tests := []test{
		{"When file access fails, return an error.", nil, errors.New("access_denied"), errors.New("access_denied")},
		{"When file access returns an unparsable key, return an error.", []byte("noKey"), nil, errors.New("Invalid Key: Key must be a PEM encoded PKCS1 or PKCS8 key")},
	}

	for _, tc := range tests {
		logger.Infof("TestGetSigningKeyErrors +++++++++++++++++ Running test: %s", tc.testName)
		ishareFileAccessor = &mockFileAccessor{map[string][]byte{"myKey": tc.testKey}, map[string]error{"myKey": tc.mockError}}
		_, err := getSigningKey("myKey")
		if err.Error() != tc.expectedError.Error() {
			t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, err)
		}
	}
}

func TestGetCertificateArrayErrors(t *testing.T) {

	logging.Log().SetLevel(logrus.DebugLevel)

	type test struct {
		testName      string
		testCerts     []byte
		mockError     error
		expectedError error
	}
	tests := []test{
		{"When file access fails, return an error.", nil, errors.New("access_denied"), errors.New("access_denied")},
		{"When file access returns a non parsable certifcate, return an error.", []byte("noCerts"), nil, errors.New("no_certificate_found")},
		{"When file access returns a certificate with invalid blocks, return an error.", []byte(invalidBlock()), nil, errors.New("x509: malformed certificate")},
		{"When file access returns a certificate with an unexpected block, return an error.", []byte(unexpectedBlock()), nil, errors.New("unexpected_block")},
	}

	for _, tc := range tests {
		logger.Infof("TestGetCertificateArrayErrors +++++++++++++++++ Running test: %s", tc.testName)
		ishareFileAccessor = &mockFileAccessor{map[string][]byte{"myCerts": tc.testCerts}, map[string]error{"myCerts": tc.mockError}}
		_, err := getCertificateArray("myCerts")
		logger.Debugf("Err %v", err)
		if err.Error() != tc.expectedError.Error() {
			t.Errorf("%s: Received an unexpected error. Expected: %v, Actual: %v", tc.testName, tc.expectedError, err)
		}
	}
}

func TestNewIShareAuthorizationRegistry(t *testing.T) {
	type test struct {
		testName           string
		isEnabled          string
		testCertPath       string
		testKeyPath        string
		testClientId       string
		testArId           string
		testArURL          string
		testDelegationPath string
		testTokenPath      string
		mockFiles          map[string][]byte
		mockErrors         map[string]error
		expectedAR         model.AuthorizationRegistry
		expectedExit       int
	}

	tests := []test{
		// disabled
		{"When iShare is disabled, no registry should be created.", "false", "", "", "", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},

		// error cases
		{"When invalid boolean is delivered, no registry should be created.", "notABool", "", "", "", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no certificate path is provided, no registry should be created.", "true", "", "", "", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no key path is provided, no registry should be created.", "true", "/credentials/certificate.pem", "", "", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no iShareClientId is provided, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no AR Id is provided, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no AR URL is provided, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no key is provided at the provided path, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "", map[string][]byte{}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When an invalid key is provided at the provided path, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "", map[string][]byte{"/credentials/key.pem": []byte("invalidKey")}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When no certificates are provided at the provided path, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "", map[string][]byte{"/credentials/key.pem": []byte(validKey())}, map[string]error{}, model.AuthorizationRegistry{}, 1},
		{"When invalid certificates are provided at the provided path, no registry should be created.", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "", map[string][]byte{"/credentials/key.pem": []byte(validKey()), "/credentials/certificate.pem": []byte(invalidBlock())}, map[string]error{}, model.AuthorizationRegistry{}, 1},

		// success
		{"When everything is provided, a proper AR should be created", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "", map[string][]byte{"/credentials/key.pem": []byte(validKey()), "/credentials/certificate.pem": []byte(validCerts())}, map[string]error{}, model.AuthorizationRegistry{Id: "ArID", Host: "http://myar.org", TokenPath: "/connect/token", DelegationPath: "/delegation"}, -1},
		{"When alternative delegation path is provided, a proper AR should be created", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "/alternative/delegation/path", "", map[string][]byte{"/credentials/key.pem": []byte(validKey()), "/credentials/certificate.pem": []byte(validCerts())}, map[string]error{}, model.AuthorizationRegistry{Id: "ArID", Host: "http://myar.org", TokenPath: "/connect/token", DelegationPath: "/alternative/delegation/path"}, -1},
		{"When alternative token path is provided, a proper AR should be created", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "", "/alternative/token/path", map[string][]byte{"/credentials/key.pem": []byte(validKey()), "/credentials/certificate.pem": []byte(validCerts())}, map[string]error{}, model.AuthorizationRegistry{Id: "ArID", Host: "http://myar.org", TokenPath: "/alternative/token/path", DelegationPath: "/delegation"}, -1},
		{"When alternative paths are provided, a proper AR should be created", "true", "/credentials/certificate.pem", "/credentials/key.pem", "myId", "ArID", "http://myar.org", "/alternative/delegation/path", "/alternative/token/path", map[string][]byte{"/credentials/key.pem": []byte(validKey()), "/credentials/certificate.pem": []byte(validCerts())}, map[string]error{}, model.AuthorizationRegistry{Id: "ArID", Host: "http://myar.org", TokenPath: "/alternative/token/path", DelegationPath: "/alternative/delegation/path"}, -1},
	}
	for _, tc := range tests {
		logger.Infof("TestNewIShareAuthorizationRegistry +++++++++++++++++ Running test: %s", tc.testName)

		// set to an unspecified exit by default and inject a spy to the logger.
		exit := -1
		logging.Log().ExitFunc = func(code int) {
			exit = code
		}

		ishareFileAccessor = &mockFileAccessor{tc.mockFiles, tc.mockErrors}
		t.Setenv(FingerprintsListEnvVar, "myFingerprint")
		t.Setenv(IShareEnabledVar, tc.isEnabled)
		t.Setenv(CertificatePathVar, tc.testCertPath)
		t.Setenv(KeyPathVar, tc.testKeyPath)
		t.Setenv(IShareClientIdVar, tc.testClientId)
		t.Setenv(AuthorizationRegistryIdVar, tc.testArId)
		t.Setenv(AuthorizationRegistryUrlVar, tc.testArURL)
		t.Setenv(ArDelegationPathVar, tc.testDelegationPath)
		t.Setenv(ArTokenPathVar, tc.testTokenPath)

		registry := NewIShareAuthorizationRegistry()

		if exit != tc.expectedExit {
			t.Errorf("%s: Did not receive the expected exit code. Expected: %d, Actual: %d.", tc.testName, tc.expectedExit, exit)
		}

		if tc.expectedExit == -1 && !cmp.Equal(tc.expectedAR, registry.pdpRegistry) {
			t.Errorf("%s: PDPRegistry not as expected. Expected: %s, Actual: %s", tc.testName, logging.PrettyPrintObject(tc.expectedAR), logging.PrettyPrintObject(registry.pdpRegistry))
		}
	}
}

func unexpectedBlock() string {

	return `-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1/Zo1+tHHeE7k
bDFATHmBFy1MZcIlsSpMWfqkoap26GWIVHuAC7EEQ+6IC26/LmKvFo5NqmN3OGFR
hZ9YRi4IOim3Vgs37hJmieyTjv5wsXcYLdiaKs3ZPIZVPGBWRWOL9wdbx6IbTP3S
xPVbKDHILmzsz/lYXRL+YSyj0YBgJygdoYbO1VuAxsgugKS3nQElcKPIaAoTAuaq
qRIT2MiryQGGzVlfb8Iv/tLq7aSDLyYagnBrxjf0tSmwUMi6l4wQBckV2ZtaRGmi
TJSTZuBlusiynh2nT3gcGUc0hjnXV8YNYIolqpBy5GEAIFi1gFtlwRIHrC8i5Kku
LH1cV6HDAgMBAAECggEAPGRv7EHTo5H0/DA7F89I8uGyEowiJUfpdXTWjBNp8hOk
vdzrLs6ya2vvmA3TLnZCIUAm8Pb+Eu4OvXLOMgj39Zr3hPN0vZavXH+glkb5gIQj
tU5hdqeFr/U5zsc+YOKd6jCLrJVO4ihmgq8BjMKF4pwlYWCSqhQY3Xl5ytMW+tDz
g+11No+8VRwHZ5MVEkMFVpOkx3bC24/N5I1ceWducrwFDql4qyjf02SL/AqwdqJZ
eZPnlcarkwQvQZiNLvsSy3XEPwGEXCK+JTUT8VRP2/gFdQoUweFXt6qWp5hlkIUT
jY4ky83UbX7qxqSZOb6RPMlhGrhcxW1AUHRMpNRSYQKBgQDxYSsBRFujVqQ/SVeF
blfDWWY6XH3tRO2NuJnPynzcDpDFUhdXU96567Ge5rhY0xHeo87FkRaim8cWcYlD
SvTtU0cf0vcS8RsjzWxu2DZ44WHq7hxhClGWz3J945KyG3JQIc/ZOCkGVd9+TnBa
oBR0woRbZXYo77b06cTcrzGtFwKBgQDBA4yvZilz7cSYM89e+eJqRfqNQ3ldPJtt
hHR6qV23Ga7MEMFpDyyEqWNjMD+B0eNdE5J1fMWyhSU7VyvrnZZDUN3tzsDH0IXc
mP4sh7jvrtGrR7zOmZ+9IF1amBuJ45rUk6NPHBbLqc9w6zuBnGqAGDZJoZTn807I
xq5iFl8UNQKBgCw6CY8p30CGV4HhBlBEb4AzmS+IUupufrhA4q3YBBit8oi1CeHO
VDjsnpbm31AnHFcW3IQGmYch09Cg7O2PhmEVqSqDlRG7a6Wbtgp5Q0HSygYpqrl9
EoX3bJr0X6SSstdL2rGKQLoQcerKpHt2aUkbevTkGkpV4cfuLUviLc/xAoGAYSUB
NPKNYIzGSvigoaPRYj2wWlMgjV3IuLlWyrndsh9aC9lPDyqU9HwwyqZpAFT8Q0dr
inhvJGfBEnnQYDkjfOQBnwRVoPwBs8LJAu6YlQH/A18K100Yyd61Pbia+66zqdRY
+KMhkgX4o1Ox0o1ASRJmmG6b/JZIC+N7t2CdIBUCgYBLL+yWKv6ZS/C/0E5MYS2j
ZS1V7+Xj7aPeojR+4hsqKuM5UIPlEtmT/pqB3wtV1T6K067D3mH3hr+MWamVjOU0
mZwiqNbHMImzY/qXSs/eaPRu0zTQJ2SuHs2FjyDEENA7mi7O0UBQM4sSMJUnT0/s
CQX2KYOmNdZoUA/bMSCV/w==
-----END PRIVATE KEY-----
`
}
func invalidBlock() string {
	return `-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
bWFsZm9ybWVk
-----END CERTIFICATE-----
`
}

func validKey() string {
	return `-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1/Zo1+tHHeE7k
bDFATHmBFy1MZcIlsSpMWfqkoap26GWIVHuAC7EEQ+6IC26/LmKvFo5NqmN3OGFR
hZ9YRi4IOim3Vgs37hJmieyTjv5wsXcYLdiaKs3ZPIZVPGBWRWOL9wdbx6IbTP3S
xPVbKDHILmzsz/lYXRL+YSyj0YBgJygdoYbO1VuAxsgugKS3nQElcKPIaAoTAuaq
qRIT2MiryQGGzVlfb8Iv/tLq7aSDLyYagnBrxjf0tSmwUMi6l4wQBckV2ZtaRGmi
TJSTZuBlusiynh2nT3gcGUc0hjnXV8YNYIolqpBy5GEAIFi1gFtlwRIHrC8i5Kku
LH1cV6HDAgMBAAECggEAPGRv7EHTo5H0/DA7F89I8uGyEowiJUfpdXTWjBNp8hOk
vdzrLs6ya2vvmA3TLnZCIUAm8Pb+Eu4OvXLOMgj39Zr3hPN0vZavXH+glkb5gIQj
tU5hdqeFr/U5zsc+YOKd6jCLrJVO4ihmgq8BjMKF4pwlYWCSqhQY3Xl5ytMW+tDz
g+11No+8VRwHZ5MVEkMFVpOkx3bC24/N5I1ceWducrwFDql4qyjf02SL/AqwdqJZ
eZPnlcarkwQvQZiNLvsSy3XEPwGEXCK+JTUT8VRP2/gFdQoUweFXt6qWp5hlkIUT
jY4ky83UbX7qxqSZOb6RPMlhGrhcxW1AUHRMpNRSYQKBgQDxYSsBRFujVqQ/SVeF
blfDWWY6XH3tRO2NuJnPynzcDpDFUhdXU96567Ge5rhY0xHeo87FkRaim8cWcYlD
SvTtU0cf0vcS8RsjzWxu2DZ44WHq7hxhClGWz3J945KyG3JQIc/ZOCkGVd9+TnBa
oBR0woRbZXYo77b06cTcrzGtFwKBgQDBA4yvZilz7cSYM89e+eJqRfqNQ3ldPJtt
hHR6qV23Ga7MEMFpDyyEqWNjMD+B0eNdE5J1fMWyhSU7VyvrnZZDUN3tzsDH0IXc
mP4sh7jvrtGrR7zOmZ+9IF1amBuJ45rUk6NPHBbLqc9w6zuBnGqAGDZJoZTn807I
xq5iFl8UNQKBgCw6CY8p30CGV4HhBlBEb4AzmS+IUupufrhA4q3YBBit8oi1CeHO
VDjsnpbm31AnHFcW3IQGmYch09Cg7O2PhmEVqSqDlRG7a6Wbtgp5Q0HSygYpqrl9
EoX3bJr0X6SSstdL2rGKQLoQcerKpHt2aUkbevTkGkpV4cfuLUviLc/xAoGAYSUB
NPKNYIzGSvigoaPRYj2wWlMgjV3IuLlWyrndsh9aC9lPDyqU9HwwyqZpAFT8Q0dr
inhvJGfBEnnQYDkjfOQBnwRVoPwBs8LJAu6YlQH/A18K100Yyd61Pbia+66zqdRY
+KMhkgX4o1Ox0o1ASRJmmG6b/JZIC+N7t2CdIBUCgYBLL+yWKv6ZS/C/0E5MYS2j
ZS1V7+Xj7aPeojR+4hsqKuM5UIPlEtmT/pqB3wtV1T6K067D3mH3hr+MWamVjOU0
mZwiqNbHMImzY/qXSs/eaPRu0zTQJ2SuHs2FjyDEENA7mi7O0UBQM4sSMJUnT0/s
CQX2KYOmNdZoUA/bMSCV/w==
-----END PRIVATE KEY-----
`
}

func validCerts() string {
	return `-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIID9zCCAt+gAwIBAgIUVUrFp9npgRF7SyY4e7NNX56hYy4wDQYJKoZIhvcNAQEL
BQAwgYoxCzAJBgNVBAYTAkRFMQ8wDQYDVQQIDAZCZXJsaW4xDzANBgNVBAcMBkJl
cmxpbjEfMB0GA1UECgwWRklXQVJFIEZvdW5kYXRpb24gZS5WLjEMMAoGA1UECwwD
RGV2MSowKAYJKoZIhvcNAQkBFhtmaXdhcmUtdGVjaC1oZWxwQGZpd2FyZS5vcmcw
HhcNMjExMTI0MTIxNTIxWhcNMjExMjI0MTIxNTIxWjCBijELMAkGA1UEBhMCREUx
DzANBgNVBAgMBkJlcmxpbjEPMA0GA1UEBwwGQmVybGluMR8wHQYDVQQKDBZGSVdB
UkUgRm91bmRhdGlvbiBlLlYuMQwwCgYDVQQLDANEZXYxKjAoBgkqhkiG9w0BCQEW
G2Zpd2FyZS10ZWNoLWhlbHBAZml3YXJlLm9yZzCCASIwDQYJKoZIhvcNAQEBBQAD
ggEPADCCAQoCggEBALX9mjX60cd4TuRsMUBMeYEXLUxlwiWxKkxZ+qShqnboZYhU
e4ALsQRD7ogLbr8uYq8Wjk2qY3c4YVGFn1hGLgg6KbdWCzfuEmaJ7JOO/nCxdxgt
2Joqzdk8hlU8YFZFY4v3B1vHohtM/dLE9VsoMcgubOzP+VhdEv5hLKPRgGAnKB2h
hs7VW4DGyC6ApLedASVwo8hoChMC5qqpEhPYyKvJAYbNWV9vwi/+0urtpIMvJhqC
cGvGN/S1KbBQyLqXjBAFyRXZm1pEaaJMlJNm4GW6yLKeHadPeBwZRzSGOddXxg1g
iiWqkHLkYQAgWLWAW2XBEgesLyLkqS4sfVxXocMCAwEAAaNTMFEwHQYDVR0OBBYE
FE4QxJE8ZXBZs9WcTpiYfMG+jlR3MB8GA1UdIwQYMBaAFE4QxJE8ZXBZs9WcTpiY
fMG+jlR3MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggEBABnhdCF2
N/RaQQsDF0lzhiEvBCkMtyd2VsNGFAryWUyujJRbXBCXq6C3umcC/jHriwuHsBYJ
FlJM8Tb8neaM2QFXQtlEoJ3T3n2wUK0+RMsqAeogQtQlUVY1NgvKeoJGupfBojEL
kAOHYqMeXPOCHN3wpHYZF0QfN1z0aiqWQBgxuWp73a+AK7H86PJI8eey3boG0GyD
toPVwW5bRgHeo595EFDpSedIrd9rHVcqwEGYFjh5FlbbKBEjNDUV4JlZu/JpMa++
DnPDd90EFWZGKsZpi3ALmya/l9DpESSMWXWe9ZCS7r6vHfLBWl58orjXuKrItmgp
YEvGmVO+2xZBuEg=
-----END CERTIFICATE-----
`
}

func nonJwtDelegationToken() string {
	return "{\"delegation_token\": \"myInvalidToken\"}"
}

func invalidChainDelegationToken() string {
	return "{\"delegation_token\":\"eyJ4NWMiOlsiTUlJRmNUQ0NBMW1nQXdJQkFnSUlTRlJKd0dBQXlqVXdEUVlKS29aSWh2Y05BUUVMQlFBd1JERVZNQk1HQTFVRUF3d01hVk5JUVZKRlZHVnpkRU5CTVEwd0N3WURWUVFMREFSVVpYTjBNUTh3RFFZRFZRUUtEQVpwVTBoQlVrVXhDekFKQmdOVkJBWVRBazVNTUI0WERURTRNRGN5TXpFMU1UUXhNMW9YRFRJek1EY3lNakUxTVRReE0xb3dTREVaTUJjR0ExVUVBd3dRYVZOSVFWSkZWR1Z6ZEVOQlgxUk1VekVOTUFzR0ExVUVDd3dFVkdWemRERVBNQTBHQTFVRUNnd0dhVk5JUVZKRk1Rc3dDUVlEVlFRR0V3Sk9URENDQWlJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dJUEFEQ0NBZ29DZ2dJQkFQdWVSWFVHU1VndTdxcEFXSmpBVkg5ejMxOVhudUZsZVZlTy9YeGJKNlU0aXhYUkt2Vzh2S1RWMWRSY2ZRZUNxWGs3dWEvWnNxTnJxODlFeDk1YjBucUdVdjFOb0syVDh5RUFrUXp5ellacFc0YzJZTUNjZzVhbVJ3Q2ZZYWhIdEptWEpXcVJFZXZNNWtKb09hY0tIL0dVYnNlbVQ5NEIwS1hTTlE2SVdjSnlqcHVhb0RwYjZXZDk3VDJsdVAxSVE1Z2tmd1UzOENaSktWa2JZM2VKa0xsT3d3dEZzRlBQMk00Zjh1NDc5T2tNVXI1L20reG43M0phWlNKRk9IdklONkRGcEFsczJheDdCaFVTbGJLTTNZRXVOYjBPNG9PNXluREZIdm1sbHA2TnUwRjJYbzBCdTBQL3VxYi8wOFh2VlduZTd3Y3dXWlI5K2Q3OHErT2xmQy9tK3dBd0FxbVFIRXI4aEpOdlI2Uy84NEhBalVkTXlHY1lUdm92MHRiMFp3L0FLd0RnOFBDOVVGUlliMGNCcjArL0dmZ21KUDVRTUFmTHFrWG1ad1lRU1oxRmFtTmxKbG14MHNZWlFTYXVkRzArWGtjOTkxK1p3L3g4dVdaaTlxUVplQk9kd25JMnhmL0hKWEhKc2FaZkR2VHA1aThpVlA3NTFyaGlud0xpMmRabm1Tc1E5Nmd2dFRRQm80SjVBdkYrczlJbCtUdWtlTHRsS0FCYW9Nd3o4d1lCQ25mS3ZVdGtwN0pVNWlqallGYXFRc0ZSM1JwT0hYY0gvc3BaVFlIdVNzMU9wSFZicjAvY0Z0V1pwdjR0U1FrbFBxQ2pkZFNBU0g5azNPQkFoeGVueVhMa245VTlBQUkzNHBaYkZWK21rc0dHck43dWtrNG9iU3RJN3ovNUFnTUJBQUdqWXpCaE1BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0h3WURWUjBqQkJnd0ZvQVVyYTNLc1RuVVZuWThLWGdsMFJpaVFCdG9LRXd3SFFZRFZSME9CQllFRkJZODV5RHAxcFR2SCtXaThiajh2dXJmTERlQk1BNEdBMVVkRHdFQi93UUVBd0lCaGpBTkJna3Foa2lHOXcwQkFRc0ZBQU9DQWdFQWVJSncxbm5vT3JzYW11ZVc0Y1pQTHpybnVIU0V2djFTRUwxYmZCNkY3M2FubXhicTkrT1lXNnFvamh4dm9ySFRGem9ReW5zUG1ic283dDRiM0hBdFdhT2xwM0RLWlVUcHpPbExuUTlnc0REZkRWU0pzSjVqeGdsREZabTBBMDdMZDNDeFpobnpXZjlBMFFnTnFONWhDY09zcmw0dURNdlp6K005a0wvaWtzQ3g0WDBzbzJPU20xUWFrcmFBUjN1bVBjMm9vQWFjUHNBVkNsbGVrWEZKOURGako1VXYrcmc4WktISExHclAxOW8vQXNYSllwS1AvdHRrNXRCdUE0SkIyMGFTaGJjQzUzOXJBK1FjK2tESHlSbkwwYUp5UlllQmdZMWlBdHV6WHpNT2s1M1hWK2FKb2dEcDNnRjczczFjMVl5SVJIdDdvZlFHLzBabHdjLzQxQ3hPRCtseXpHMzRSa2dJVU82VWZqaUdDRlBtWlEySGtwS3lxTGlmcmFSZHFySFhPaG9WZDdIaWRZSWloblpLRGtMaTFjZmVvMm16OHRXaVV6QStkUGNoYUlFbHBRSlBUalNiTGpGMkkxOVF5QjhmdVBhelBmTklqSHJYYUtsYVMzbHVLY0ZpcU9ZZ2N3V2ZkWm1EenhJVTZQWTJiengvU0RNb1UyNHJBVlN1R0FZQklBbHdmMnB4bXRMY2JNQTZiWXI0dHJtUWZiSnJNOGY4SlpnR1FvSXRycHpyS2pCSjJnRlJ0KzA2NU5NVE5rQjVydzhYcjU2ajVkamtxQjAvcUhJY0YyVGlZL2svODFSbVRDWXhyVkh6TTFjemhYSFhZenZuZDJKbDF3Slh5YWNXbDdGaVBhZ2d3MFlRaWRXSEdNZEl0RXVELzhTWGlDWGwxT0l2dmljPSIsIk1JSUZiVENDQTFXZ0F3SUJBZ0lJSGpqZlR1U2pGak13RFFZSktvWklodmNOQVFFTEJRQXdSREVWTUJNR0ExVUVBd3dNYVZOSVFWSkZWR1Z6ZEVOQk1RMHdDd1lEVlFRTERBUlVaWE4wTVE4d0RRWURWUVFLREFacFUwaEJVa1V4Q3pBSkJnTlZCQVlUQWs1TU1CNFhEVEU0TURjeU16RTFNRFV4TTFvWERUSTRNRGN5TURFMU1EVXhNMW93UkRFVk1CTUdBMVVFQXd3TWFWTklRVkpGVkdWemRFTkJNUTB3Q3dZRFZRUUxEQVJVWlhOME1ROHdEUVlEVlFRS0RBWnBVMGhCVWtVeEN6QUpCZ05WQkFZVEFrNU1NSUlDSWpBTkJna3Foa2lHOXcwQkFRRUZBQU9DQWc4QU1JSUNDZ0tDQWdFQTRISVEyZUdYU1AwYnFnT3M2SWJyeFR3LzB1Nlh5Umk1SC9aK2o4aFB6RmVTL243VWNEcys0OEdZU2dFTjFjSURCQUdXam53Tk02dTRScFFpRzh4bDdZdGpXeW13S200SFh0TEFRcXQ3MmFyWTM3UFNGMzBYaTZWUEJhbnRQVGRhYSs5ekNVOEN5Rm5FWjJmS1RrMVN1ZzM2ZzZGNk9qZGdDQ0dramRwcEtWeU5JbDVPVytrakZxMkE5R3Z0QlJHRXdSMmV0b3RLdHNJSEkvZzRjWE9GWmp0Q0N0UG9FbWpRNjZmU3dhN0Fqb2xwQmIyUGNzc0NWcGI1YzZzQWZwMjBKTm44NGtEUUVvSGplb3lOQXFjdEJFSXNSWkY0a3BUbjRZaFNYcTBUSC9rUnRFRWZORW16TEVPU2FEV1B5TDhxSkpweDFhUEF5ZTBma0dmSmk1MWNHUnJGeGY3amZOOTlUamRmM3l4d3RUL3lRcXVXTHA2VkxkcWpKTGs5YnRHaytCaVM5aVZ0dzQxRWMyeXNYLzNnMHhlVlZGR3R5Q3dBQ1dweUl4K1FtODBLalZYa1lEeGhHaUxRalFJelZvbFBFVlVEQVpudytMQ21nM09ZOUl5MFBYVFYweDNDS0hNK0MzdWtaV2tTMWQzQ1NnRFZsMStjcEhKVDRtNmZLbm5jTzc3eVZPMHlyVzUyMThVR2FZQUxPaDhQSG93MzZlOWNCMmMwYlQyZDFDSFJla1NsNCtCeCt4UU1Hd3NQeXZlR2dwa0hpZFp0WVJEUDRFL0h4Tkt5K3dmQnlRZVN1NFljVWM4RUh4eTlxenhhZTI4UWZabjdzNDdWL1BqQWswZExaeVFEb25FOVExME9rTVYxNURwOVBXR2VDUUpyaTVKZE9ucitpRDhEZEhzQ0F3RUFBYU5qTUdFd0R3WURWUjBUQVFIL0JBVXdBd0VCL3pBZkJnTlZIU01FR0RBV2dCU3RyY3F4T2RSV2Rqd3BlQ1hSR0tKQUcyZ29UREFkQmdOVkhRNEVGZ1FVcmEzS3NUblVWblk4S1hnbDBSaWlRQnRvS0V3d0RnWURWUjBQQVFIL0JBUURBZ0dHTUEwR0NTcUdTSWIzRFFFQkN3VUFBNElDQVFCQ0dZTmwvMUhGV1ZoRG9QbWtwVnFtMzByeXFmNmRXeDFyeFRXMWxrOWFWVU9sUjlJUkhQcDF6L0YvNGZiNm1JWEZqRll3NWxVMmZhSFY5b3A0ck51R3FSUlNMaVFQVnZPWHhEbHhxQTZEbXF6aVJFdnR0RzB1TFovRk95Y0tZNTNwV0ZDekcya2VxNk9JZDlKU3BGbVFET2lGN1dTdWlmUEx1d0FEa1V3K29aWUdnV21id1FPMGxYdHc3WE9ueTM3bkxaa1lsODliUmhJZy83ZmIrWG5iODkxNFNNdjBrR2xrMWtDZXlMNkZYZFhSVGFhdDVjOVhsSnI5eXpPVUlEbjU0YlkxQktUNll0aXlKZnZDTmF2L0ZiMjR2NWVxMlo5bUJkWjcwQ2M5NWdQanFxeE1aVWdKbzU3WXZoTGZYRHd4YldaV1lDK1djUjhuSGtZK3RaQmxJaWgyQ1hIc09hcjVvSDZkck1kdE1JWnozVVpKL0N4RkcxdTIzVXoxakJmbS9FZ2dkS2hPVm5UNmVkcnVWb3RlV1dDREI5SGRoeHo4UkFWWW41ZHFVamtqUnE0VzlRQWZKdXNyUFpHQm5kVDd5TmFZL0ZIWUtJcSt1VGFyV2liamR4dGRZQ2xhVHdPeGs1SXFLTkY5ZUNLYlBteHMxbWxaclNMak1RRlkzVTlSa3Z6SSszSWxBRmtjdFVlYWJwa21YeG51V1dTVjJGSk85WnJPTk1XdXR3KzU2N1BLNWd6TTBGcVF2YjdzQ3hadVFEbDVDdDZaV2x0czJZNzJ0NnBQalJJMTcrUzgrK2EydlFkeEJjTlEweEYydGp2elR2aVozQzVFcUllYXpXZGdJWmtxZldaa1M4diswTUF2TlpZK2JieCt2U3dMT29IUVdyZi9PQ0w3QVE9PSJdLCJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJFVS5FT1JJLk5MMDAwMDAwMDA0Iiwic3ViIjoiT1JERVJfUkVBREVSIiwianRpIjoiMmM0ZGI2NmUyYjgyNDUzZTg1NTRhZTgwNmJkN2FhMGQiLCJpYXQiOjE2Njk3MzA5NzUsImV4cCI6MTY2OTczMTAwNSwiYXVkIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsImRlbGVnYXRpb25FdmlkZW5jZSI6eyJub3RCZWZvcmUiOjE2Njc4MjMyNzIsIm5vdE9uT3JBZnRlciI6MTY2NzkwOTgzMywicG9saWN5SXNzdWVyIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsInRhcmdldCI6eyJhY2Nlc3NTdWJqZWN0IjoiT1JERVJfUkVBREVSIn0sInBvbGljeVNldHMiOlt7Im1heERlbGVnYXRpb25EZXB0aCI6MCwidGFyZ2V0Ijp7ImVudmlyb25tZW50Ijp7ImxpY2Vuc2VzIjpbIklTSEFSRS4wMDAxIl19fSwicG9saWNpZXMiOlt7InRhcmdldCI6eyJyZXNvdXJjZSI6eyJ0eXBlIjoidCIsImlkZW50aWZpZXJzIjpbIioiXSwiYXR0cmlidXRlcyI6WyIqIl19fSwicnVsZXMiOlt7ImVmZmVjdCI6IkRlbnkifV19XX1dfX0.tpvGsXXsas-j6Dxwzwu_G5HtUDMBJKmqJ2QuQMR1uCbFeojXI-V3w01eU5Swey7gUpzC2jyUKUlV0yCUwC3-G0oT4WS0Xa32sDFb0EwUI4Gz4rmH1IXomg7VAvTsMOwIJ-RxDur-3xNLEW0xeeE_phsw6-v--pN35lArhSQgEUlCwTSUVPdwNklrdGSDyka9e9-LMXVCiSvX4kdwpQY_CObBgi0w6dgR1Q17WJIb6hiHNmIb9J52lbjAvpj-vgmwmP1D2vGs0KXCm20YsNXfL2q3ABhSPubpI0WI2At7vaqgOVBHc3fSiRyl7XYEPAazx24lsV3pkDgbIhERZLHbiw\"}"
}

func invalidDelegationToken() string {
	return "{\"delegation_token\": \"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJFVS5FT1JJLk5MMDAwMDAwMDA0Iiwic3ViIjoiT1JERVJfUkVBREVSIiwianRpIjoiMmM0ZGI2NmUyYjgyNDUzZTg1NTRhZTgwNmJkN2FhMGQiLCJpYXQiOjE2Njk3MzA5NzUsImV4cCI6MTY2OTczMTAwNSwiYXVkIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsImRlbGVnYXRpb25FdmlkZW5jZSI6eyJub3RCZWZvcmUiOjE2Njc4MjMyNzIsIm5vdE9uT3JBZnRlciI6MTY2NzkwOTgzMywicG9saWN5SXNzdWVyIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsInRhcmdldCI6eyJhY2Nlc3NTdWJqZWN0IjoiT1JERVJfUkVBREVSIn0sInBvbGljeVNldHMiOlt7Im1heERlbGVnYXRpb25EZXB0aCI6MCwidGFyZ2V0Ijp7ImVudmlyb25tZW50Ijp7ImxpY2Vuc2VzIjpbIklTSEFSRS4wMDAxIl19fSwicG9saWNpZXMiOlt7InRhcmdldCI6eyJyZXNvdXJjZSI6eyJ0eXBlIjoidCIsImlkZW50aWZpZXJzIjpbIioiXSwiYXR0cmlidXRlcyI6WyIqIl19fSwicnVsZXMiOlt7ImVmZmVjdCI6IkRlbnkifV19XX1dfX0.tpvGsXXsas-j6Dxwzwu_G5HtUDMBJKmqJ2QuQMR1uCbFeojXI-V3w01eU5Swey7gUpzC2jyUKUlV0yCUwC3-G0oT4WS0Xa32sDFb0EwUI4Gz4rmH1IXomg7VAvTsMOwIJ-RxDur-3xNLEW0xeeE_phsw6-v--pN35lArhSQgEUlCwTSUVPdwNklrdGSDyka9e9-LMXVCiSvX4kdwpQY_CObBgi0w6dgR1Q17WJIb6hiHNmIb9J52lbjAvpj-vgmwmP1D2vGs0KXCm20YsNXfL2q3ABhSPubpI0WI2At7vaqgOVBHc3fSiRyl7XYEPAazx24lsV3pkDgbIhERZLHbiw\"}"
}

func expiredDelegationToken() string {
	return "{\"delegation_token\":\"eyJ4NWMiOlsiTUlJRXR6Q0NBcCtnQXdJQkFnSUlRU1JCL0d2ODl3a3dEUVlKS29aSWh2Y05BUUVMQlFBd1NERVpNQmNHQTFVRUF3d1FhVk5JUVZKRlZHVnpkRU5CWDFSTVV6RU5NQXNHQTFVRUN3d0VWR1Z6ZERFUE1BMEdBMVVFQ2d3R2FWTklRVkpGTVFzd0NRWURWUVFHRXdKT1REQWVGdzB5TVRBeU1UZ3hNak15TXpoYUZ3MHlNekF5TVRneE1qTXlNemhhTUhneEt6QXBCZ05WQkFNTUltbFRTRUZTUlNCVVpYTjBJRUYxZEdodmNtbDZZWFJwYjI0Z1VtVm5hWE4wY25reEhEQWFCZ05WQkFVVEUwVlZMa1ZQVWtrdVRrd3dNREF3TURBd01EUXhEVEFMQmdOVkJBc01CRlJsYzNReER6QU5CZ05WQkFvTUJtbFRTRUZTUlRFTE1Ba0dBMVVFQmhNQ1Rrd3dnZ0VpTUEwR0NTcUdTSWIzRFFFQkFRVUFBNElCRHdBd2dnRUtBb0lCQVFDOFMxUjlLV3hBYmtha04xZGtMUmxmZ2VsY2t0Y1hOYkhNRUpsTkFyVWI3bHpmaTZxOEFneFJiendoR09hZmllRWFTTlJGdWZkUlRVWnl2QXhtQWFSVnU0QmFUUzJzYlJFZG5XclVqRzNJTUl5MElMdHNkZXhIOUxRVzhSOXU5RmxIaDNiTUVXMXdQTjhDQVFFZHBGMDhQWGhobEJ4ZGdsd2w4eW9BOGlTNVpyWkZUVTlGdFMwUnN5TFMzTHc2UXZGNGZKUG5mNXFPUUpaTWYwa1E4dmNwSzFBSk51SnptSzJuMmVsN2pkcU1oYWtoV2tTWWpzZkZqKzdNTFV2SjJuYUV2S0tEQWJnZFZlZW55a2UxT2RqcWdEQkF5cFFtdjV2KzZmeERIQmFUQjZoejFBTXhFR3NSMlE1TEpRWXdiYkZ0alVFa1BDMzE3NlczYktXclRKcDFBZ01CQUFHamRUQnpNQXdHQTFVZEV3RUIvd1FDTUFBd0h3WURWUjBqQkJnd0ZvQVVGanpuSU9uV2xPOGY1YUx4dVB5KzZ0OHNONEV3RXdZRFZSMGxCQXd3Q2dZSUt3WUJCUVVIQXdFd0hRWURWUjBPQkJZRUZPZjRoMXBpd3Zid1ZnMTFpM3NoMVVMT3h5YUdNQTRHQTFVZER3RUIvd1FFQXdJRm9EQU5CZ2txaGtpRzl3MEJBUXNGQUFPQ0FnRUFKWkh0SjFnME04aW5FTGdUMDN4OHJuM2xXQWtQUFJXVEd2SjBkSnA0QTZDb0wxMGgyemJ5VG5UalI4d0J2MVBtQTNneGQ2UlNvM0pRU2I4amNZdVdjN1V0MTl1QjROWXEvSFJPRXdXYm0vYnpDK2dnbXFGY05HZkVOVzQ4NksvRk9xQ0RsZHlMTmRSeGpBbThMU1VqSkVMN0Q0amx6cUhMbkgyN0haNm1TK1pVYUFMSnpnclMyeWNsYWZ1Q1dHT0hRc2cweDdIa1cvU25MZXVNS3A0Y1hpaXpZVnhUV2JDb1doYit2VloxOFVvZXN1RzdvaUg2TENxL1BsY3I2Tkt2SFQyRjBCbnhJYS8rRFA4QTV4K3hPajRPYlh0cERuSlRxSmwzMmhwQ3JLeW4xUDY4SG9iR0NScjhsZWxJM0p6OXFWQnlaNlVSd2RKY2E1eEltb0lScTM2ZHZoL2E0SWtyeXpOYThDUlI5cEU2akM0VWdoeHgrb2tjV3VWWlk5RjJ4Z1VlMjE4bGRycFpBcDhac1MzUjZEUmtyRytid29BNWt3OTlyd0o5ak5uR0JWbzFzQUc0ZjVHQ281TERDM280eHBvUzllSThNZ1BEbWNxYUdZWjFoVjQyeGs2MkhVdUVjdkpEOWtORjBVZkF0enNHWXhQMkgwdXNLUm92NCtHYlUyeVVxcEhTRDlVb2lUcE9HQldEVDhIOGU2NmI4aFpZYWdXbElnYTg1OHJUbEZUQm1hMlhmNXVaaUJUbFdCQjE2c1VCbjFWS1h4M2RwQi95eEJaeEd1WjBieTIyS0Q5bnFCamtPbWpveEN5SGMyRnR2dEdYV2ZFZGlTT3hqakcvb3dqNWdndE8ySC9CQmdvQzJNd2x2N1dDdXlzVEFmVEpBakFxY3lzUkpPOD0iLCJNSUlGY1RDQ0ExbWdBd0lCQWdJSVNGUkp3R0FBeWpVd0RRWUpLb1pJaHZjTkFRRUxCUUF3UkRFVk1CTUdBMVVFQXd3TWFWTklRVkpGVkdWemRFTkJNUTB3Q3dZRFZRUUxEQVJVWlhOME1ROHdEUVlEVlFRS0RBWnBVMGhCVWtVeEN6QUpCZ05WQkFZVEFrNU1NQjRYRFRFNE1EY3lNekUxTVRReE0xb1hEVEl6TURjeU1qRTFNVFF4TTFvd1NERVpNQmNHQTFVRUF3d1FhVk5JUVZKRlZHVnpkRU5CWDFSTVV6RU5NQXNHQTFVRUN3d0VWR1Z6ZERFUE1BMEdBMVVFQ2d3R2FWTklRVkpGTVFzd0NRWURWUVFHRXdKT1REQ0NBaUl3RFFZSktvWklodmNOQVFFQkJRQURnZ0lQQURDQ0Fnb0NnZ0lCQVB1ZVJYVUdTVWd1N3FwQVdKakFWSDl6MzE5WG51RmxlVmVPL1h4Yko2VTRpeFhSS3ZXOHZLVFYxZFJjZlFlQ3FYazd1YS9ac3FOcnE4OUV4OTViMG5xR1V2MU5vSzJUOHlFQWtRenl6WVpwVzRjMllNQ2NnNWFtUndDZllhaEh0Sm1YSldxUkVldk01a0pvT2FjS0gvR1Vic2VtVDk0QjBLWFNOUTZJV2NKeWpwdWFvRHBiNldkOTdUMmx1UDFJUTVna2Z3VTM4Q1pKS1ZrYlkzZUprTGxPd3d0RnNGUFAyTTRmOHU0NzlPa01VcjUvbSt4bjczSmFaU0pGT0h2SU42REZwQWxzMmF4N0JoVVNsYktNM1lFdU5iME80b081eW5ERkh2bWxscDZOdTBGMlhvMEJ1MFAvdXFiLzA4WHZWV25lN3djd1daUjkrZDc4cStPbGZDL20rd0F3QXFtUUhFcjhoSk52UjZTLzg0SEFqVWRNeUdjWVR2b3YwdGIwWncvQUt3RGc4UEM5VUZSWWIwY0JyMCsvR2ZnbUpQNVFNQWZMcWtYbVp3WVFTWjFGYW1ObEpsbXgwc1laUVNhdWRHMCtYa2M5OTErWncveDh1V1ppOXFRWmVCT2R3bkkyeGYvSEpYSEpzYVpmRHZUcDVpOGlWUDc1MXJoaW53TGkyZFpubVNzUTk2Z3Z0VFFCbzRKNUF2RitzOUlsK1R1a2VMdGxLQUJhb013ejh3WUJDbmZLdlV0a3A3SlU1aWpqWUZhcVFzRlIzUnBPSFhjSC9zcFpUWUh1U3MxT3BIVmJyMC9jRnRXWnB2NHRTUWtsUHFDamRkU0FTSDlrM09CQWh4ZW55WExrbjlVOUFBSTM0cFpiRlYrbWtzR0dyTjd1a2s0b2JTdEk3ei81QWdNQkFBR2pZekJoTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3SHdZRFZSMGpCQmd3Rm9BVXJhM0tzVG5VVm5ZOEtYZ2wwUmlpUUJ0b0tFd3dIUVlEVlIwT0JCWUVGQlk4NXlEcDFwVHZIK1dpOGJqOHZ1cmZMRGVCTUE0R0ExVWREd0VCL3dRRUF3SUJoakFOQmdrcWhraUc5dzBCQVFzRkFBT0NBZ0VBZUlKdzFubm9PcnNhbXVlVzRjWlBMenJudUhTRXZ2MVNFTDFiZkI2RjczYW5teGJxOStPWVc2cW9qaHh2b3JIVEZ6b1F5bnNQbWJzbzd0NGIzSEF0V2FPbHAzREtaVVRwek9sTG5ROWdzRERmRFZTSnNKNWp4Z2xERlptMEEwN0xkM0N4WmhueldmOUEwUWdOcU41aENjT3NybDR1RE12WnorTTlrTC9pa3NDeDRYMHNvMk9TbTFRYWtyYUFSM3VtUGMyb29BYWNQc0FWQ2xsZWtYRko5REZqSjVVdityZzhaS0hITEdyUDE5by9Bc1hKWXBLUC90dGs1dEJ1QTRKQjIwYVNoYmNDNTM5ckErUWMra0RIeVJuTDBhSnlSWWVCZ1kxaUF0dXpYek1PazUzWFYrYUpvZ0RwM2dGNzNzMWMxWXlJUkh0N29mUUcvMFpsd2MvNDFDeE9EK2x5ekczNFJrZ0lVTzZVZmppR0NGUG1aUTJIa3BLeXFMaWZyYVJkcXJIWE9ob1ZkN0hpZFlJaWhuWktEa0xpMWNmZW8ybXo4dFdpVXpBK2RQY2hhSUVscFFKUFRqU2JMakYySTE5UXlCOGZ1UGF6UGZOSWpIclhhS2xhUzNsdUtjRmlxT1lnY3dXZmRabUR6eElVNlBZMmJ6eC9TRE1vVTI0ckFWU3VHQVlCSUFsd2YycHhtdExjYk1BNmJZcjR0cm1RZmJKck04ZjhKWmdHUW9JdHJwenJLakJKMmdGUnQrMDY1Tk1UTmtCNXJ3OFhyNTZqNWRqa3FCMC9xSEljRjJUaVkvay84MVJtVENZeHJWSHpNMWN6aFhIWFl6dm5kMkpsMXdKWHlhY1dsN0ZpUGFnZ3cwWVFpZFdIR01kSXRFdUQvOFNYaUNYbDFPSXZ2aWM9IiwiTUlJRmJUQ0NBMVdnQXdJQkFnSUlIampmVHVTakZqTXdEUVlKS29aSWh2Y05BUUVMQlFBd1JERVZNQk1HQTFVRUF3d01hVk5JUVZKRlZHVnpkRU5CTVEwd0N3WURWUVFMREFSVVpYTjBNUTh3RFFZRFZRUUtEQVpwVTBoQlVrVXhDekFKQmdOVkJBWVRBazVNTUI0WERURTRNRGN5TXpFMU1EVXhNMW9YRFRJNE1EY3lNREUxTURVeE0xb3dSREVWTUJNR0ExVUVBd3dNYVZOSVFWSkZWR1Z6ZEVOQk1RMHdDd1lEVlFRTERBUlVaWE4wTVE4d0RRWURWUVFLREFacFUwaEJVa1V4Q3pBSkJnTlZCQVlUQWs1TU1JSUNJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBZzhBTUlJQ0NnS0NBZ0VBNEhJUTJlR1hTUDBicWdPczZJYnJ4VHcvMHU2WHlSaTVIL1orajhoUHpGZVMvbjdVY0RzKzQ4R1lTZ0VOMWNJREJBR1dqbndOTTZ1NFJwUWlHOHhsN1l0ald5bXdLbTRIWHRMQVFxdDcyYXJZMzdQU0YzMFhpNlZQQmFudFBUZGFhKzl6Q1U4Q3lGbkVaMmZLVGsxU3VnMzZnNkY2T2pkZ0NDR2tqZHBwS1Z5TklsNU9XK2tqRnEyQTlHdnRCUkdFd1IyZXRvdEt0c0lISS9nNGNYT0ZaanRDQ3RQb0VtalE2NmZTd2E3QWpvbHBCYjJQY3NzQ1ZwYjVjNnNBZnAyMEpObjg0a0RRRW9IamVveU5BcWN0QkVJc1JaRjRrcFRuNFloU1hxMFRIL2tSdEVFZk5FbXpMRU9TYURXUHlMOHFKSnB4MWFQQXllMGZrR2ZKaTUxY0dSckZ4ZjdqZk45OVRqZGYzeXh3dFQveVFxdVdMcDZWTGRxakpMazlidEdrK0JpUzlpVnR3NDFFYzJ5c1gvM2cweGVWVkZHdHlDd0FDV3B5SXgrUW04MEtqVlhrWUR4aEdpTFFqUUl6Vm9sUEVWVURBWm53K0xDbWczT1k5SXkwUFhUVjB4M0NLSE0rQzN1a1pXa1MxZDNDU2dEVmwxK2NwSEpUNG02ZktubmNPNzd5Vk8weXJXNTIxOFVHYVlBTE9oOFBIb3czNmU5Y0IyYzBiVDJkMUNIUmVrU2w0K0J4K3hRTUd3c1B5dmVHZ3BrSGlkWnRZUkRQNEUvSHhOS3krd2ZCeVFlU3U0WWNVYzhFSHh5OXF6eGFlMjhRZlpuN3M0N1YvUGpBazBkTFp5UURvbkU5UTEwT2tNVjE1RHA5UFdHZUNRSnJpNUpkT25yK2lEOERkSHNDQXdFQUFhTmpNR0V3RHdZRFZSMFRBUUgvQkFVd0F3RUIvekFmQmdOVkhTTUVHREFXZ0JTdHJjcXhPZFJXZGp3cGVDWFJHS0pBRzJnb1REQWRCZ05WSFE0RUZnUVVyYTNLc1RuVVZuWThLWGdsMFJpaVFCdG9LRXd3RGdZRFZSMFBBUUgvQkFRREFnR0dNQTBHQ1NxR1NJYjNEUUVCQ3dVQUE0SUNBUUJDR1lObC8xSEZXVmhEb1Bta3BWcW0zMHJ5cWY2ZFd4MXJ4VFcxbGs5YVZVT2xSOUlSSFBwMXovRi80ZmI2bUlYRmpGWXc1bFUyZmFIVjlvcDRyTnVHcVJSU0xpUVBWdk9YeERseHFBNkRtcXppUkV2dHRHMHVMWi9GT3ljS1k1M3BXRkN6RzJrZXE2T0lkOUpTcEZtUURPaUY3V1N1aWZQTHV3QURrVXcrb1pZR2dXbWJ3UU8wbFh0dzdYT255MzduTFprWWw4OWJSaElnLzdmYitYbmI4OTE0U012MGtHbGsxa0NleUw2RlhkWFJUYWF0NWM5WGxKcjl5ek9VSURuNTRiWTFCS1Q2WXRpeUpmdkNOYXYvRmIyNHY1ZXEyWjltQmRaNzBDYzk1Z1BqcXF4TVpVZ0pvNTdZdmhMZlhEd3hiV1pXWUMrV2NSOG5Ia1krdFpCbElpaDJDWEhzT2FyNW9INmRyTWR0TUlaejNVWkovQ3hGRzF1MjNVejFqQmZtL0VnZ2RLaE9WblQ2ZWRydVZvdGVXV0NEQjlIZGh4ejhSQVZZbjVkcVVqa2pScTRXOVFBZkp1c3JQWkdCbmRUN3lOYVkvRkhZS0lxK3VUYXJXaWJqZHh0ZFlDbGFUd094azVJcUtORjllQ0tiUG14czFtbFpyU0xqTVFGWTNVOVJrdnpJKzNJbEFGa2N0VWVhYnBrbVh4bnVXV1NWMkZKTzlack9OTVd1dHcrNTY3UEs1Z3pNMEZxUXZiN3NDeFp1UURsNUN0NlpXbHRzMlk3MnQ2cFBqUkkxNytTOCsrYTJ2UWR4QmNOUTB4RjJ0anZ6VHZpWjNDNUVxSWVheldkZ0laa3FmV1prUzh2KzBNQXZOWlkrYmJ4K3ZTd0xPb0hRV3JmL09DTDdBUT09Il0sImFsZyI6IlJTMjU2IiwidHlwIjoiSldUIn0.eyJpc3MiOiJFVS5FT1JJLk5MMDAwMDAwMDA0Iiwic3ViIjoiT1JERVJfUkVBREVSIiwianRpIjoiMmM0ZGI2NmUyYjgyNDUzZTg1NTRhZTgwNmJkN2FhMGQiLCJpYXQiOjE2Njk3MzA5NzUsImV4cCI6MTY2OTczMTAwNSwiYXVkIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsImRlbGVnYXRpb25FdmlkZW5jZSI6eyJub3RCZWZvcmUiOjE2Njc4MjMyNzIsIm5vdE9uT3JBZnRlciI6MTY2NzkwOTgzMywicG9saWN5SXNzdWVyIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyIsInRhcmdldCI6eyJhY2Nlc3NTdWJqZWN0IjoiT1JERVJfUkVBREVSIn0sInBvbGljeVNldHMiOlt7Im1heERlbGVnYXRpb25EZXB0aCI6MCwidGFyZ2V0Ijp7ImVudmlyb25tZW50Ijp7ImxpY2Vuc2VzIjpbIklTSEFSRS4wMDAxIl19fSwicG9saWNpZXMiOlt7InRhcmdldCI6eyJyZXNvdXJjZSI6eyJ0eXBlIjoidCIsImlkZW50aWZpZXJzIjpbIioiXSwiYXR0cmlidXRlcyI6WyIqIl19fSwicnVsZXMiOlt7ImVmZmVjdCI6IkRlbnkifV19XX1dfX0.tpvGsXXsas-j6Dxwzwu_G5HtUDMBJKmqJ2QuQMR1uCbFeojXI-V3w01eU5Swey7gUpzC2jyUKUlV0yCUwC3-G0oT4WS0Xa32sDFb0EwUI4Gz4rmH1IXomg7VAvTsMOwIJ-RxDur-3xNLEW0xeeE_phsw6-v--pN35lArhSQgEUlCwTSUVPdwNklrdGSDyka9e9-LMXVCiSvX4kdwpQY_CObBgi0w6dgR1Q17WJIb6hiHNmIb9J52lbjAvpj-vgmwmP1D2vGs0KXCm20YsNXfL2q3ABhSPubpI0WI2At7vaqgOVBHc3fSiRyl7XYEPAazx24lsV3pkDgbIhERZLHbiw\"}"
}

func validDelegationToken() string {
	return "{\"delegation_token\":\"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlEOXpDQ0F0K2dBd0lCQWdJVVZVckZwOW5wZ1JGN1N5WTRlN05OWDU2aFl5NHdEUVlKS29aSWh2Y05BUUVMQlFBd2dZb3hDekFKQmdOVkJBWVRBa1JGTVE4d0RRWURWUVFJREFaQ1pYSnNhVzR4RHpBTkJnTlZCQWNNQmtKbGNteHBiakVmTUIwR0ExVUVDZ3dXUmtsWFFWSkZJRVp2ZFc1a1lYUnBiMjRnWlM1V0xqRU1NQW9HQTFVRUN3d0RSR1YyTVNvd0tBWUpLb1pJaHZjTkFRa0JGaHRtYVhkaGNtVXRkR1ZqYUMxb1pXeHdRR1pwZDJGeVpTNXZjbWN3SGhjTk1qRXhNVEkwTVRJeE5USXhXaGNOTWpFeE1qSTBNVEl4TlRJeFdqQ0JpakVMTUFrR0ExVUVCaE1DUkVVeER6QU5CZ05WQkFnTUJrSmxjbXhwYmpFUE1BMEdBMVVFQnd3R1FtVnliR2x1TVI4d0hRWURWUVFLREJaR1NWZEJVa1VnUm05MWJtUmhkR2x2YmlCbExsWXVNUXd3Q2dZRFZRUUxEQU5FWlhZeEtqQW9CZ2txaGtpRzl3MEJDUUVXRzJacGQyRnlaUzEwWldOb0xXaGxiSEJBWm1sM1lYSmxMbTl5WnpDQ0FTSXdEUVlKS29aSWh2Y05BUUVCQlFBRGdnRVBBRENDQVFvQ2dnRUJBTFg5bWpYNjBjZDRUdVJzTVVCTWVZRVhMVXhsd2lXeEtreForcVNocW5ib1pZaFVlNEFMc1FSRDdvZ0xicjh1WXE4V2prMnFZM2M0WVZHRm4xaEdMZ2c2S2JkV0N6ZnVFbWFKN0pPTy9uQ3hkeGd0MkpvcXpkazhobFU4WUZaRlk0djNCMXZIb2h0TS9kTEU5VnNvTWNndWJPelArVmhkRXY1aExLUFJnR0FuS0IyaGhzN1ZXNERHeUM2QXBMZWRBU1Z3bzhob0NoTUM1cXFwRWhQWXlLdkpBWWJOV1Y5dndpLyswdXJ0cElNdkpocUNjR3ZHTi9TMUtiQlF5THFYakJBRnlSWFptMXBFYWFKTWxKTm00R1c2eUxLZUhhZFBlQndaUnpTR09kZFh4ZzFnaWlXcWtITGtZUUFnV0xXQVcyWEJFZ2VzTHlMa3FTNHNmVnhYb2NNQ0F3RUFBYU5UTUZFd0hRWURWUjBPQkJZRUZFNFF4SkU4WlhCWnM5V2NUcGlZZk1HK2psUjNNQjhHQTFVZEl3UVlNQmFBRkU0UXhKRThaWEJaczlXY1RwaVlmTUcramxSM01BOEdBMVVkRXdFQi93UUZNQU1CQWY4d0RRWUpLb1pJaHZjTkFRRUxCUUFEZ2dFQkFCbmhkQ0YyTi9SYVFRc0RGMGx6aGlFdkJDa010eWQyVnNOR0ZBcnlXVXl1akpSYlhCQ1hxNkMzdW1jQy9qSHJpd3VIc0JZSkZsSk04VGI4bmVhTTJRRlhRdGxFb0ozVDNuMndVSzArUk1zcUFlb2dRdFFsVVZZMU5ndktlb0pHdXBmQm9qRUxrQU9IWXFNZVhQT0NITjN3cEhZWkYwUWZOMXowYWlxV1FCZ3h1V3A3M2ErQUs3SDg2UEpJOGVleTNib0cwR3lEdG9QVndXNWJSZ0hlbzU5NUVGRHBTZWRJcmQ5ckhWY3F3RUdZRmpoNUZsYmJLQkVqTkRVVjRKbFp1L0pwTWErK0RuUERkOTBFRldaR0tzWnBpM0FMbXlhL2w5RHBFU1NNV1hXZTlaQ1M3cjZ2SGZMQldsNThvcmpYdUtySXRtZ3BZRXZHbVZPKzJ4WkJ1RWc9IiwiTUlJRDl6Q0NBdCtnQXdJQkFnSVVWVXJGcDlucGdSRjdTeVk0ZTdOTlg1NmhZeTR3RFFZSktvWklodmNOQVFFTEJRQXdnWW94Q3pBSkJnTlZCQVlUQWtSRk1ROHdEUVlEVlFRSURBWkNaWEpzYVc0eER6QU5CZ05WQkFjTUJrSmxjbXhwYmpFZk1CMEdBMVVFQ2d3V1JrbFhRVkpGSUVadmRXNWtZWFJwYjI0Z1pTNVdMakVNTUFvR0ExVUVDd3dEUkdWMk1Tb3dLQVlKS29aSWh2Y05BUWtCRmh0bWFYZGhjbVV0ZEdWamFDMW9aV3h3UUdacGQyRnlaUzV2Y21jd0hoY05NakV4TVRJME1USXhOVEl4V2hjTk1qRXhNakkwTVRJeE5USXhXakNCaWpFTE1Ba0dBMVVFQmhNQ1JFVXhEekFOQmdOVkJBZ01Ca0psY214cGJqRVBNQTBHQTFVRUJ3d0dRbVZ5YkdsdU1SOHdIUVlEVlFRS0RCWkdTVmRCVWtVZ1JtOTFibVJoZEdsdmJpQmxMbFl1TVF3d0NnWURWUVFMREFORVpYWXhLakFvQmdrcWhraUc5dzBCQ1FFV0cyWnBkMkZ5WlMxMFpXTm9MV2hsYkhCQVptbDNZWEpsTG05eVp6Q0NBU0l3RFFZSktvWklodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQUxYOW1qWDYwY2Q0VHVSc01VQk1lWUVYTFV4bHdpV3hLa3haK3FTaHFuYm9aWWhVZTRBTHNRUkQ3b2dMYnI4dVlxOFdqazJxWTNjNFlWR0ZuMWhHTGdnNktiZFdDemZ1RW1hSjdKT08vbkN4ZHhndDJKb3F6ZGs4aGxVOFlGWkZZNHYzQjF2SG9odE0vZExFOVZzb01jZ3ViT3pQK1ZoZEV2NWhMS1BSZ0dBbktCMmhoczdWVzRER3lDNkFwTGVkQVNWd284aG9DaE1DNXFxcEVoUFl5S3ZKQVliTldWOXZ3aS8rMHVydHBJTXZKaHFDY0d2R04vUzFLYkJReUxxWGpCQUZ5UlhabTFwRWFhSk1sSk5tNEdXNnlMS2VIYWRQZUJ3WlJ6U0dPZGRYeGcxZ2lpV3FrSExrWVFBZ1dMV0FXMlhCRWdlc0x5TGtxUzRzZlZ4WG9jTUNBd0VBQWFOVE1GRXdIUVlEVlIwT0JCWUVGRTRReEpFOFpYQlpzOVdjVHBpWWZNRytqbFIzTUI4R0ExVWRJd1FZTUJhQUZFNFF4SkU4WlhCWnM5V2NUcGlZZk1HK2psUjNNQThHQTFVZEV3RUIvd1FGTUFNQkFmOHdEUVlKS29aSWh2Y05BUUVMQlFBRGdnRUJBQm5oZENGMk4vUmFRUXNERjBsemhpRXZCQ2tNdHlkMlZzTkdGQXJ5V1V5dWpKUmJYQkNYcTZDM3VtY0MvakhyaXd1SHNCWUpGbEpNOFRiOG5lYU0yUUZYUXRsRW9KM1QzbjJ3VUswK1JNc3FBZW9nUXRRbFVWWTFOZ3ZLZW9KR3VwZkJvakVMa0FPSFlxTWVYUE9DSE4zd3BIWVpGMFFmTjF6MGFpcVdRQmd4dVdwNzNhK0FLN0g4NlBKSThlZXkzYm9HMEd5RHRvUFZ3VzViUmdIZW81OTVFRkRwU2VkSXJkOXJIVmNxd0VHWUZqaDVGbGJiS0JFak5EVVY0SmxadS9KcE1hKytEblBEZDkwRUZXWkdLc1pwaTNBTG15YS9sOURwRVNTTVdYV2U5WkNTN3I2dkhmTEJXbDU4b3JqWHVLckl0bWdwWUV2R21WTysyeFpCdUVnPSIsIk1JSUQ5ekNDQXQrZ0F3SUJBZ0lVVlVyRnA5bnBnUkY3U3lZNGU3Tk5YNTZoWXk0d0RRWUpLb1pJaHZjTkFRRUxCUUF3Z1lveEN6QUpCZ05WQkFZVEFrUkZNUTh3RFFZRFZRUUlEQVpDWlhKc2FXNHhEekFOQmdOVkJBY01Ca0psY214cGJqRWZNQjBHQTFVRUNnd1dSa2xYUVZKRklFWnZkVzVrWVhScGIyNGdaUzVXTGpFTU1Bb0dBMVVFQ3d3RFJHVjJNU293S0FZSktvWklodmNOQVFrQkZodG1hWGRoY21VdGRHVmphQzFvWld4d1FHWnBkMkZ5WlM1dmNtY3dIaGNOTWpFeE1USTBNVEl4TlRJeFdoY05NakV4TWpJME1USXhOVEl4V2pDQmlqRUxNQWtHQTFVRUJoTUNSRVV4RHpBTkJnTlZCQWdNQmtKbGNteHBiakVQTUEwR0ExVUVCd3dHUW1WeWJHbHVNUjh3SFFZRFZRUUtEQlpHU1ZkQlVrVWdSbTkxYm1SaGRHbHZiaUJsTGxZdU1Rd3dDZ1lEVlFRTERBTkVaWFl4S2pBb0Jna3Foa2lHOXcwQkNRRVdHMlpwZDJGeVpTMTBaV05vTFdobGJIQkFabWwzWVhKbExtOXlaekNDQVNJd0RRWUpLb1pJaHZjTkFRRUJCUUFEZ2dFUEFEQ0NBUW9DZ2dFQkFMWDltalg2MGNkNFR1UnNNVUJNZVlFWExVeGx3aVd4S2t4WitxU2hxbmJvWlloVWU0QUxzUVJEN29nTGJyOHVZcThXamsycVkzYzRZVkdGbjFoR0xnZzZLYmRXQ3pmdUVtYUo3Sk9PL25DeGR4Z3QySm9xemRrOGhsVThZRlpGWTR2M0IxdkhvaHRNL2RMRTlWc29NY2d1Yk96UCtWaGRFdjVoTEtQUmdHQW5LQjJoaHM3Vlc0REd5QzZBcExlZEFTVndvOGhvQ2hNQzVxcXBFaFBZeUt2SkFZYk5XVjl2d2kvKzB1cnRwSU12SmhxQ2NHdkdOL1MxS2JCUXlMcVhqQkFGeVJYWm0xcEVhYUpNbEpObTRHVzZ5TEtlSGFkUGVCd1pSelNHT2RkWHhnMWdpaVdxa0hMa1lRQWdXTFdBVzJYQkVnZXNMeUxrcVM0c2ZWeFhvY01DQXdFQUFhTlRNRkV3SFFZRFZSME9CQllFRkU0UXhKRThaWEJaczlXY1RwaVlmTUcramxSM01COEdBMVVkSXdRWU1CYUFGRTRReEpFOFpYQlpzOVdjVHBpWWZNRytqbFIzTUE4R0ExVWRFd0VCL3dRRk1BTUJBZjh3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUJuaGRDRjJOL1JhUVFzREYwbHpoaUV2QkNrTXR5ZDJWc05HRkFyeVdVeXVqSlJiWEJDWHE2QzN1bWNDL2pIcml3dUhzQllKRmxKTThUYjhuZWFNMlFGWFF0bEVvSjNUM24yd1VLMCtSTXNxQWVvZ1F0UWxVVlkxTmd2S2VvSkd1cGZCb2pFTGtBT0hZcU1lWFBPQ0hOM3dwSFlaRjBRZk4xejBhaXFXUUJneHVXcDczYStBSzdIODZQSkk4ZWV5M2JvRzBHeUR0b1BWd1c1YlJnSGVvNTk1RUZEcFNlZElyZDlySFZjcXdFR1lGamg1RmxiYktCRWpORFVWNEpsWnUvSnBNYSsrRG5QRGQ5MEVGV1pHS3NacGkzQUxteWEvbDlEcEVTU01XWFdlOVpDUzdyNnZIZkxCV2w1OG9yalh1S3JJdG1ncFlFdkdtVk8rMnhaQnVFZz0iXX0.eyJhdWQiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIiwiZGVsZWdhdGlvbkV2aWRlbmNlIjp7Im5vdEJlZm9yZSI6MTY2NzgyMzI3Miwibm90T25PckFmdGVyIjoxNjY3OTA5ODMzLCJwb2xpY3lJc3N1ZXIiOiJFVS5FT1JJLk5MSEFQUFlQRVRTIiwicG9saWN5U2V0cyI6W3sibWF4RGVsZWdhdGlvbkRlcHRoIjowLCJwb2xpY2llcyI6W3sicnVsZXMiOlt7ImVmZmVjdCI6IkRlbnkifV0sInRhcmdldCI6eyJyZXNvdXJjZSI6eyJhdHRyaWJ1dGVzIjpbIioiXSwiaWRlbnRpZmllcnMiOlsiKiJdLCJ0eXBlIjoidCJ9fX1dLCJ0YXJnZXQiOnsiZW52aXJvbm1lbnQiOnsibGljZW5zZXMiOlsiSVNIQVJFLjAwMDEiXX19fV0sInRhcmdldCI6eyJhY2Nlc3NTdWJqZWN0IjoiT1JERVJfUkVBREVSIn19LCJleHAiOjI1NTMzNDUxODAsImlhdCI6MTY2OTczMDk3NSwiaXNzIjoiRVUuRU9SSS5OTDAwMDAwMDAwNCIsImp0aSI6IjJjNGRiNjZlMmI4MjQ1M2U4NTU0YWU4MDZiZDdhYTBkIiwic3ViIjoiRVUuRU9SSS5OTEhBUFBZUEVUUyJ9.Ndtc4qTx4agZkYQ7ccZQwiKIaAXmWVdPxfhVBPi3engQCtBm3K0ICbqjVOEh4nod02ov8MWcbfxL4yWblZ3qSE8MC0_mPSZx_t_rBib-gRZsUM51eIREzxGAp-i2-PXh4GOmOEbJFdnw9zGDNLJPm2U7gnG6WqtGwZU6UNkP8LcRpYSHhQkixY9MNkWbOTBna4k9sZHsav56CVfZsnF1NsCj2G9pW9b_a0FOG46N4_hlzto_vKv8A98xGe90wTHB5FLjP1CnnvUQo-5KMrClErj7mZzICUivmCNKMqduhv1OKQ-9jeftiTXFWToXis-QDMLtJgn79FlTTrU97kae8g\"}"
}

func evidenceFromToken() *model.DelegationEvidence {
	evidence := model.DelegationEvidence{
		NotBefore:    1667823272,
		NotOnOrAfter: 1667909833,
		PolicyIssuer: "EU.EORI.NLHAPPYPETS",
		PolicySets: []model.PolicySet{
			{
				MaxDelegationDepth: 0,
				Policies: []model.Policy{
					{
						Rules: []model.Rule{
							{
								Effect: "Deny",
							},
						},
						Target: &model.PolicyTarget{
							Resource: &model.Resource{
								Attributes:  []string{"*"},
								Identifiers: []string{"*"},
								Type:        "t",
							},
						},
					},
				},
				Target: &model.PolicySetTarget{
					Environment: &model.PolicySetEnvironment{
						Licenses: []string{"ISHARE.0001"},
					},
				},
			},
		},
		Target: model.DelegationTarget{
			AccessSubject: "ORDER_READER",
		},
	}
	return &evidence
}

func notFoundResponse() *http.Response {
	nfR := http.Response{StatusCode: 404}
	return &nfR
}

func forbiddenResponse() *http.Response {
	fR := http.Response{StatusCode: 403}
	return &fR
}

func tokenResponse() *http.Response {
	tR := http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader("{\"access_token\": \"myToken\"}"))}
	return &tR
}
