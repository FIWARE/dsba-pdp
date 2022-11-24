package config

import (
	"os"

	"github.com/wistefan/dsba-pdp/logging"
)

var providerId string

var logger = logging.Log()

func ProviderId() string {
	return providerId
}

func init() {
	providerId = os.Getenv("PROVIDER_ID")
	if providerId == "" {
		logger.Warnf("No provider id configured, use an empty provider.")
	}
}
