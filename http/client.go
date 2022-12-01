package http

import (
	"net/http"
	"net/url"
)

/**
* Global http client
 */
var globalHttpClient httpClient = &http.Client{}

func HttpClient() httpClient {
	return globalHttpClient
}

// Interface to the http-client
type httpClient interface {
	Do(req *http.Request) (*http.Response, error)
	PostForm(url string, data url.Values) (*http.Response, error)
}
