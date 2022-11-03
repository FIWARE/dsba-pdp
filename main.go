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
* Url of the authorization registry to use
 */
var authorizationRegistyUrl string

/**
* Port to run the pdp at. Default is 8080.
 */
var serverPort int = 8080

/**
* Global http client
 */
var globalHttpClient httpClient = &http.Client{}

/**
* Startup method to run the gin-server.
 */
func main() {

	router := gin.Default()

	router.POST("/authz", authorize)

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

	if enableJsonLogging {
		logger.SetFormatter(&logrus.JSONFormatter{})
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
