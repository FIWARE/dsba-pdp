package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hellofresh/health-go/v5"
)

/**
* Version of the component. Should be overwritten by linker flags with the real version.
 */
var Version = "development"

/**
* Pointer to the health check. Can be used to register additional components to check
 */
var healthCheck *health.Health

func init() {
	healthCheck, _ = health.New(health.WithComponent(health.Component{
		Name:    "dsba-pdp",
		Version: Version,
	}))
}

func HealthReq(c *gin.Context) {
	checkResult := healthCheck.Measure(c.Request.Context())
	if checkResult.Status == health.StatusOK {
		c.AbortWithStatusJSON(http.StatusOK, checkResult)
	} else {
		c.AbortWithStatusJSON(http.StatusServiceUnavailable, checkResult)
	}
}

func Health() *health.Health {
	return healthCheck
}
