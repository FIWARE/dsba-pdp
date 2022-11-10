package main

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

/**
* Global logger
 */
var logger = logrus.New()

/**
* Port to run the pdp at. Default is 8080.
 */
var serverPort int = 8080

/**
* Global http client
 */
var globalHttpClient httpClient = &http.Client{}

/**
* Repository used to store trusted issuers
 */
var issuerRepo IssuerRepository

func init() {
	dbEnabled, dbErr := strconv.ParseBool(os.Getenv("DB_ENABLED"))

	if dbErr != nil && dbEnabled {
		logger.Fatal("DB is not yet supported.")
		return
	}
	logger.Warn("Issuer repository is kept in-memory. No persistence will be applied, do NEVER use this for anything but development or testing!")
	issuerRepo = InMemoryRepo{}
}

/**
* Startup method to run the gin-server.
 */
func main() {

	router := gin.Default()

	//pdp authz
	router.POST("/authz", authorize)

	// verification
	router.POST("/verifiy", verifyIssuer)

	//issuer list
	router.POST("/issuer", createTrustedIssuer)
	router.GET("/issuer", getIssuers)
	router.PUT("/issuer/:id", replaceIssuer)
	router.GET("/issuer/:id", getIssuerById)
	router.DELETE("/issuer/:id", deleteIssuerById)

	router.Run(fmt.Sprintf("0.0.0.0:%v", serverPort))
	logger.Infof("Started router at %v", serverPort)
}

func init() {

	serverPortEnvVar := os.Getenv("SERVER_PORT")
	enableJsonLogging, err := strconv.ParseBool(os.Getenv("JSON_LOGGING_ENABLED"))

	if err != nil {
		logger.Warnf("Json log env-var not readable. Use default logging. %v", err)
		enableJsonLogging = false
	}
	logLevel := os.Getenv("LOG_LEVEL")

	if logLevel == "DEBUG" {
		logger.SetLevel(logrus.DebugLevel)
	} else if logLevel == "INFO" {
		logger.SetLevel(logrus.InfoLevel)
	} else if logLevel == "WARN" {
		logger.SetLevel(logrus.WarnLevel)
	} else if logLevel == "ERROR" {
		logger.SetLevel(logrus.ErrorLevel)
	}

	if enableJsonLogging {
		logger.SetFormatter(&logrus.JSONFormatter{})
	} else {
		logger.SetFormatter(&logrus.TextFormatter{})
	}

	serverPort, err = strconv.Atoi(serverPortEnvVar)
	if err != nil {
		logger.Fatalf("No valid server port was provided, run on default %s.", serverPort)
	}
}

// Interface to the http-client
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}
