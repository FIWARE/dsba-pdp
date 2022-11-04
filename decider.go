package main

// interface of the configured decider

type Decider interface {
	Decide(token string, originalAddress string, requestType string, requestBody *map[string]interface{}) (descision Decision, err httpError)
}

// error interface

type Decision struct {
	Decision bool   `json:"decision`
	Reason   string `json:"reason"`
}

type httpError struct {
	status    int
	message   string
	rootError error
}

func (err *httpError) Error() string {
	return err.message
}

func (err *httpError) GetRoot() error {
	return err.rootError
}
