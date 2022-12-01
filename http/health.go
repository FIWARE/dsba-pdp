package http

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/hellofresh/health-go/v5"
)

var healthCheck *health.Health

func init() {
	healthCheck, _ = health.New(health.WithComponent(health.Component{
		Name: "dsba-pdp",
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
