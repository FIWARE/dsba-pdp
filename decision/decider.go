package decision

import "github.com/wistefan/dsba-pdp/model"

// interface of the configured decider

type Decider interface {
	Decide(token *model.DSBAToken, originalAddress string, requestType string, requestBody *map[string]interface{}) (descision model.Decision, err model.HttpError)
}
