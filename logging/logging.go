package logging

import (
	"encoding/json"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
)

/**
* Global logger
 */
var logger = logrus.New()

var skipPaths []string = []string{}
var logRequests bool = true

func Log() *logrus.Logger {
	return logger
}

func GinHandlerFunc() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !logRequests {
			c.Next()
		} else {
			// Start timer
			start := time.Now()
			path := c.Request.URL.Path
			raw := c.Request.URL.RawQuery
			if raw != "" {
				path = path + "?" + raw
			}

			// Process request
			c.Next()

			if contains(skipPaths, path) {
				return
			}

			// Stop timer
			end := time.Now()
			latency := end.Sub(start)
			method := c.Request.Method
			statusCode := c.Writer.Status()
			errorMessage := c.Errors.ByType(gin.ErrorTypePrivate).String()

			if errorMessage != "" {
				Log().Warnf("Request [%s]%s took %d ms - Result: %d - %s", method, path, latency, statusCode, errorMessage)
			} else {
				Log().Infof("Request [%s]%s took %d ms - Result: %d", method, path, latency, statusCode)
			}
		}
	}
}

/**
* Helper method to print objects with json-serialization information in a more human readable way
 */
func PrettyPrintObject(objectInterface interface{}) string {
	jsonBytes, err := json.Marshal(objectInterface)
	if err != nil {
		logger.Debugf("Was not able to pretty print the object: %v", objectInterface)
		return ""
	}
	return string(jsonBytes)
}

func init() {
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

	skipPathsEnv := os.Getenv("LOG_SKIP_PATHS")
	logRequests, err = strconv.ParseBool(os.Getenv("LOG_REQUESTS"))
	if err != nil {
		logger.Warnf("Invalid LOG_REQUESTS configured, will enable request logging by default. Err: %v.", err)
	}

	if skipPathsEnv != "" {
		skipPaths = strings.Split(skipPathsEnv, ",")
		logger.Infof("Will skip request logging for paths %s.", skipPaths)
	}
}

func contains(s []string, e string) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}
	return false
}
