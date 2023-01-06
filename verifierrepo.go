package main

import (
	"context"
	"os"
	"strings"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

const TrustedVerifiersVar = "TRUSTED_VERIFIERS"

type VerifierRepository struct {
	jwkCache  *jwk.Cache
	verifiers []string
}

func NewVerifierRepository() *VerifierRepository {
	logger.Info("Starting the verifier repository.")

	trustedVerifiers := os.Getenv(TrustedVerifiersVar)

	ctx := context.Background()
	verifierRepository := new(VerifierRepository)
	verifierRepository.jwkCache = jwk.NewCache(ctx)
	verifierRepository.verifiers = strings.Split(trustedVerifiers, ",")
	for _, tv := range verifierRepository.verifiers {
		_, err := verifierRepository.jwkCache.Refresh(ctx, tv)
		if err != nil {
			logger.Warnf("Was not able to initially get the jwk from %s. Will continue anyways. Err: %s.", tv, err)
		}

		logger.Debugf("Initiated the verifier %s.", tv)
	}
	return verifierRepository
}

func (verifierRepository *VerifierRepository) Get() jwk.Set {

	jwkSet := jwk.NewSet()

	for _, tv := range verifierRepository.verifiers {

		keyset, err := verifierRepository.jwkCache.Get(context.Background(), tv)
		if err != nil {
			logger.Warnf("Was not able to retrieve keys for %s. Error: %s", tv, err)
		} else {
			logger.Infof("Got keys %v", keyset)
			for key := keyset.Keys(context.Background()); key.Next(context.Background()); {
				jwkSet.AddKey(key.Pair().Value.(jwk.Key))
			}
		}
	}
	return jwkSet
}
