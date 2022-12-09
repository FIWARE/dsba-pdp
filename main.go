package main

import (
	"fmt"
	"os"
	"strconv"

	"github.com/fiware/dsba-pdp/http"
	"github.com/fiware/dsba-pdp/logging"
	"github.com/fiware/dsba-pdp/trustedissuer"
	"github.com/penglongli/gin-metrics/ginmetrics"

	"github.com/gin-gonic/gin"
)

/**
* Port to run the pdp at. Default is 8080.
 */
var serverPort int = 8080

var logger = logging.Log()

/**
* Startup method to run the gin-server.
 */
func main() {

	router := gin.New()
	// inject our logger
	router.Use(logging.GinHandlerFunc(), gin.Recovery())

	// health check
	router.GET("/health", http.HealthReq)

	//pdp authz
	router.POST("/authz", authorize)

	// verification
	router.POST("/verify", trustedissuer.VerifyIssuer)

	//issuer list
	router.POST("/issuer", trustedissuer.CreateTrustedIssuer)
	router.GET("/issuer", trustedissuer.GetIssuers)
	router.PUT("/issuer/:id", trustedissuer.ReplaceIssuer)
	router.GET("/issuer/:id", trustedissuer.GetIssuerById)
	router.DELETE("/issuer/:id", trustedissuer.DeleteIssuerById)

	// initiate metrics
	metrics := ginmetrics.GetMonitor()
	metrics.SetMetricPath("/metrics")
	metrics.Use(router)

	router.Run(fmt.Sprintf("0.0.0.0:%v", serverPort))

	logger.Infof("Started router at %v", serverPort)
}

func init() {

	serverPortEnvVar := os.Getenv("SERVER_PORT")

	serverPortEnv, err := strconv.Atoi(serverPortEnvVar)
	if err != nil {
		logger.Warnf("No valid server port was provided, run on default %d.", serverPort)
	} else {
		serverPort = serverPortEnv
	}
}
