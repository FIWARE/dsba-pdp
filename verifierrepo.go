package main

import (
	"context"
	"errors"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/procyon-projects/chrono"
)

const TrustedVerifiersVar = "TRUSTED_VERIFIERS"
const JwkUpdateIntervalVar = "JWK_UPDATE_INTERVAL_IN_S"

const defaultUpdateInterval = 10

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

	updateInterval, err := strconv.Atoi(os.Getenv(JwkUpdateIntervalVar))
	if err != nil {
		logger.Warn("No valid update interval for the jwk configured, will use the default.")
		updateInterval = defaultUpdateInterval
	}

	taskScheduler.ScheduleAtFixedRate(verifierRepository.UpdateKeyMap, time.Duration(updateInterval)*time.Second)
	return verifierRepository
}

func (verifierRepository *VerifierRepository) UpdateKeyMap(ctx context.Context) {
	logger.Debug("Updating the key map.")
	for _, tv := range verifierRepository.verifiers {
		keyset, err := verifierRepository.jwkCache.Get(context.Background(), tv)
		if err != nil {
			logger.Warnf("Was not able to retrieve keys for %s. Error: %s", tv, err)
			// force a refresh. if the verifier is not available on last get, the cached object is not valid and needs to be fetched
			verifierRepository.jwkCache.Refresh(context.Background(), tv)
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
