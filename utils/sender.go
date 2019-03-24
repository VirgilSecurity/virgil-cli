package utils

import (
	"github.com/VirgilSecurity/virgil-cli/client"
	"net/http"
)

func SendWithCheckRetry(vcli *client.VirgilHttpClient, method string, urlPath string, payload interface{}, respObj interface{}, extraOptions ...interface{}) (headers http.Header, cookie string, err error) {
	token, err := LoadAccessTokenOrLogin(vcli)

	if err != nil {
		return nil, "", err
	}

	var vErr *client.VirgilAPIError
	for vErr == nil {
		headers, cookie, vErr = vcli.Send(method, token, urlPath, payload, respObj, extraOptions)
		if vErr == nil {
			break
		}

		token, err = CheckRetry(vErr, vcli)
	}

	return
}
