package decision

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/wistefan/dsba-pdp/model"
)

type TokenParser struct {
	Clock Clock
}

type Clock interface {
	Now() time.Time
}

type RealClock struct{}

func (c RealClock) Now() time.Time {
	return time.Now()
}

func (tp *TokenParser) parseIShareToken(tokenString string) (parsedToken *model.IShareToken, httpErr model.HttpError) {
	token, err := jwt.ParseWithClaims(tokenString, &model.IShareToken{}, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodRSA); !ok {
			return nil, fmt.Errorf("invalid_token_method")
		}

		x5cInterfaces := (*token).Header["x5c"].([]interface{})
		// the first in the chain is the client cert
		decodedClientCert, err := base64.StdEncoding.DecodeString(x5cInterfaces[0].(string))
		if err != nil {
			logger.Warnf("The client cert could not be decoded. Token: %s", tokenString)
			return nil, err
		}
		clientCert, err := x509.ParseCertificate(decodedClientCert)
		if err != nil {
			logger.Warnf("The client cert could not be parsed. Token: %s", tokenString)
			return nil, err
		}

		rootPool := x509.NewCertPool()
		intermediatePool := x509.NewCertPool()
		lastCert := len(x5cInterfaces) - 1
		for i, cert := range x5cInterfaces {
			if i == 0 {
				// skip client cert
				continue
			}
			decodedCert, err := base64.StdEncoding.DecodeString(cert.(string))
			if err != nil {
				logger.Warnf("The cert could not be decoded. Cert: %s", cert.(string))
				return nil, err
			}
			parsedCert, err := x509.ParseCertificate(decodedCert)
			if err != nil {
				logger.Warnf("The cert could not be parsed. Cert: %s", cert.(string))
				return nil, err
			}
			if i == lastCert {
				rootPool.AddCert(parsedCert)
				continue
			}
			intermediatePool.AddCert(parsedCert)
		}

		logger.Debugf("Its now %v", tp.Clock.Now())
		opts := x509.VerifyOptions{Roots: rootPool, Intermediates: intermediatePool, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}, CurrentTime: tp.Clock.Now()}
		if _, err := clientCert.Verify(opts); err != nil {
			logger.Warnf("The cert could not be verified.")
			return nil, err
		}

		logger.Debugf("Parsed certificate is: %v", clientCert)
		return clientCert.PublicKey.(*rsa.PublicKey), nil
	})

	if err != nil {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Was not able to parse token. Error: %v", err), RootError: err}
	}
	if !token.Valid {
		return parsedToken, model.HttpError{Status: http.StatusBadGateway, Message: fmt.Sprintf("Did not receive a valid token. Error: %v", err), RootError: err}
	}
	return token.Claims.(*model.IShareToken), httpErr

}
