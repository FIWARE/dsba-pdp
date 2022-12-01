package config

import (
	"os"

	"github.com/wistefan/dsba-pdp/logging"
)

var providerId string

var logger = logging.Log()

type Config interface {
	ProviderId() string
}

type EnvConfig struct{}

func (EnvConfig) ProviderId() string {
	providerId = os.Getenv("PROVIDER_ID")
	if providerId == "" {
		logger.Warnf("No provider id configured, use an empty provider.")
	}
	return providerId
}
