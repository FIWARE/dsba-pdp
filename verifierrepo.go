package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/procyon-projects/chrono"
)

const TrustedVerifiersVar = "TRUSTED_VERIFIERS"

type VerifierRepository struct {
	jwkCache  *jwk.Cache
	verifiers []string
	keyMap    map[string]jwk.Key
}

func NewVerifierRepository() *VerifierRepository {
	logger.Info("Starting the verifier repository.")

	trustedVerifiers := os.Getenv(TrustedVerifiersVar)

	ctx := context.Background()
	verifierRepository := new(VerifierRepository)
	verifierRepository.jwkCache = jwk.NewCache(ctx)
	verifierRepository.verifiers = strings.Split(trustedVerifiers, ",")
	for _, tv := range verifierRepository.verifiers {
		err := verifierRepository.jwkCache.Register(tv)
		if err != nil {
			logger.Warnf("Was not able to regsiter verifier %s, will skip it.", tv)
			continue
		}
		_, err = verifierRepository.jwkCache.Refresh(ctx, tv)
		if err != nil {
			logger.Warnf("Was not able to initially get the jwk from %s. Will continue anyways. Err: %s.", tv, err)
		}

		logger.Debugf("Initiated the verifier %s.", tv)
	}
	verifierRepository.keyMap = map[string]jwk.Key{}
	taskScheduler := chrono.NewDefaultTaskScheduler()
	taskScheduler.ScheduleAtFixedRate(verifierRepository.UpdateKeyMap, time.Duration(time.Duration(10).Seconds()))
	return verifierRepository
}

func (verifierRepository *VerifierRepository) UpdateKeyMap(ctx context.Context) {
	logger.Debug("Updating the key map.")
	for _, tv := range verifierRepository.verifiers {
		keyset, err := verifierRepository.jwkCache.Get(context.Background(), tv)
		if err != nil {
			logger.Warnf("Was not able to retrieve keys for %s. Error: %s", tv, err)
		} else {
			logger.Debugf("Got keys %v", keyset)
			for key := keyset.Keys(context.Background()); key.Next(context.Background()); {
				keyId := key.Pair().Value.(jwk.Key).KeyID()
				logger.Debugf("Update key %s.", keyId)
				verifierRepository.keyMap[keyId] = key.Pair().Value.(jwk.Key)
			}
		}
	}
}

func (verifierRepository *VerifierRepository) GetKey(keyId string) (key jwk.Key, err error) {

	key, ok := verifierRepository.keyMap[keyId]
	if !ok {
		logger.Warnf("No key with the id %s exists.", keyId)
		return key, errors.New("no_such_key_exists")
	}
	return key, err
}