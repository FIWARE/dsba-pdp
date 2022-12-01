package logging

import (
	"encoding/json"
	"os"
	"strconv"

	"github.com/sirupsen/logrus"
)

/**
* Global logger
 */
var logger = logrus.New()

func Log() *logrus.Logger {
	return logger
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
}
