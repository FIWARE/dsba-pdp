package decision

import (
	"time"

	"github.com/fiware/dsba-pdp/model"
)

// interface of the configured decider

type Decider interface {
	Decide(credential *model.DSBAVerifiableCredential, originalAddress string, requestType string, requestBody *map[string]interface{}) (descision model.Decision, err model.HttpError)
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (c RealClock) Now() time.Time {
	return time.Now()
}
