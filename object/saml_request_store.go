// Copyright 2026 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package object

import (
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/beego/beego/v2/core/logs"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/util"
	"github.com/redis/go-redis/v9"
)

const (
	samlRequestRedisPrefix = "casdoor:saml_request:"
	SamlRequestTTL         = 5 * time.Minute
)

type SamlRequestState struct {
	SessionId      string    `json:"sessionId"`
	ProviderId     string    `json:"providerId"`
	RelayStateHash string    `json:"relayStateHash"`
	ExpiresAt      time.Time `json:"expiresAt"`
}

type samlRequestStore interface {
	Store(requestId string, state SamlRequestState) error
	Load(requestId string) (SamlRequestState, bool, error)
	LoadAndDelete(requestId string) (SamlRequestState, bool, error)
	DeleteExpired(now time.Time)
}

var pendingSamlRequests samlRequestStore = newMemorySamlRequestStore()

func InitSamlRequestStore() {
	endpoint := conf.GetConfigString("redisEndpoint")
	if endpoint != "" {
		client, err := newRedisClient(endpoint)
		if err != nil {
			pendingSamlRequests = &failedSamlRequestStore{err: fmt.Errorf("SAML request store unavailable: %w", err)}
			logs.Error("saml_request_store: Redis is configured but unavailable; SAML login is disabled: %v", err)
			return
		}
		pendingSamlRequests = &redisSamlRequestStore{client: client}
		logs.Info("saml_request_store: using configured Redis backend")
		return
	}

	util.SafeGoroutine(func() {
		ticker := time.NewTicker(time.Minute)
		defer ticker.Stop()
		for now := range ticker.C {
			pendingSamlRequests.DeleteExpired(now)
		}
	})
}

func NewSamlRequestState(sessionId, providerId, relayState string, now time.Time) SamlRequestState {
	return SamlRequestState{
		SessionId:      sessionId,
		ProviderId:     providerId,
		RelayStateHash: hashSamlRelayState(relayState),
		ExpiresAt:      now.Add(SamlRequestTTL),
	}
}

func StoreSamlRequest(requestId string, state SamlRequestState) error {
	if requestId == "" || state.SessionId == "" || state.ProviderId == "" || state.RelayStateHash == "" {
		return fmt.Errorf("invalid SAML request state")
	}
	return pendingSamlRequests.Store(requestId, state)
}

func LoadSamlRequest(requestId string) (SamlRequestState, bool, error) {
	return pendingSamlRequests.Load(requestId)
}

func ConsumeSamlRequest(requestId string) (SamlRequestState, bool, error) {
	return pendingSamlRequests.LoadAndDelete(requestId)
}

func ValidateSamlRequestState(state SamlRequestState, sessionId, providerId, relayState string, now time.Time) error {
	if !now.Before(state.ExpiresAt) {
		return fmt.Errorf("SAML authentication request has expired")
	}
	if subtle.ConstantTimeCompare([]byte(state.SessionId), []byte(sessionId)) != 1 ||
		subtle.ConstantTimeCompare([]byte(state.ProviderId), []byte(providerId)) != 1 ||
		subtle.ConstantTimeCompare([]byte(state.RelayStateHash), []byte(hashSamlRelayState(relayState))) != 1 {
		return fmt.Errorf("SAML response does not match this browser session")
	}
	return nil
}

func SameSamlRequestState(left, right SamlRequestState) bool {
	return left.SessionId == right.SessionId &&
		left.ProviderId == right.ProviderId &&
		left.RelayStateHash == right.RelayStateHash &&
		left.ExpiresAt.Equal(right.ExpiresAt)
}

func hashSamlRelayState(relayState string) string {
	digest := sha256.Sum256([]byte(relayState))
	return hex.EncodeToString(digest[:])
}

type memorySamlRequestStore struct {
	mu      sync.Mutex
	entries map[string]SamlRequestState
}

func newMemorySamlRequestStore() *memorySamlRequestStore {
	return &memorySamlRequestStore{entries: map[string]SamlRequestState{}}
}

func (s *memorySamlRequestStore) Store(requestId string, state SamlRequestState) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.entries[requestId]; exists {
		return fmt.Errorf("duplicate SAML authentication request")
	}
	s.entries[requestId] = state
	return nil
}

func (s *memorySamlRequestStore) Load(requestId string) (SamlRequestState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.entries[requestId]
	return state, ok, nil
}

func (s *memorySamlRequestStore) LoadAndDelete(requestId string) (SamlRequestState, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	state, ok := s.entries[requestId]
	if ok {
		delete(s.entries, requestId)
	}
	return state, ok, nil
}

func (s *memorySamlRequestStore) DeleteExpired(now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for requestId, state := range s.entries {
		if !now.Before(state.ExpiresAt) {
			delete(s.entries, requestId)
		}
	}
}

type redisSamlRequestStore struct {
	client *redis.Client
}

func (s *redisSamlRequestStore) key(requestId string) string {
	digest := sha256.Sum256([]byte(requestId))
	return samlRequestRedisPrefix + hex.EncodeToString(digest[:])
}

func (s *redisSamlRequestStore) Store(requestId string, state SamlRequestState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	ttl := time.Until(state.ExpiresAt)
	if ttl <= 0 {
		return fmt.Errorf("SAML authentication request has expired")
	}
	stored, err := s.client.SetNX(context.Background(), s.key(requestId), data, ttl).Result()
	if err != nil {
		return err
	}
	if !stored {
		return fmt.Errorf("duplicate SAML authentication request")
	}
	return nil
}

func (s *redisSamlRequestStore) Load(requestId string) (SamlRequestState, bool, error) {
	data, err := s.client.Get(context.Background(), s.key(requestId)).Bytes()
	if err == redis.Nil {
		return SamlRequestState{}, false, nil
	}
	if err != nil {
		return SamlRequestState{}, false, err
	}
	var state SamlRequestState
	if err = json.Unmarshal(data, &state); err != nil {
		return SamlRequestState{}, false, err
	}
	return state, true, nil
}

func (s *redisSamlRequestStore) LoadAndDelete(requestId string) (SamlRequestState, bool, error) {
	data, err := s.client.GetDel(context.Background(), s.key(requestId)).Bytes()
	if err == redis.Nil {
		return SamlRequestState{}, false, nil
	}
	if err != nil {
		return SamlRequestState{}, false, err
	}
	var state SamlRequestState
	if err = json.Unmarshal(data, &state); err != nil {
		return SamlRequestState{}, false, err
	}
	return state, true, nil
}

func (s *redisSamlRequestStore) DeleteExpired(time.Time) {}

type failedSamlRequestStore struct {
	err error
}

func (s *failedSamlRequestStore) Store(string, SamlRequestState) error {
	return s.err
}
func (s *failedSamlRequestStore) Load(string) (SamlRequestState, bool, error) {
	return SamlRequestState{}, false, s.err
}
func (s *failedSamlRequestStore) LoadAndDelete(string) (SamlRequestState, bool, error) {
	return SamlRequestState{}, false, s.err
}
func (s *failedSamlRequestStore) DeleteExpired(time.Time) {}
