package model

import (
	"encoding/json"

	"github.com/deepmap/oapi-codegen/pkg/runtime"
)

type TrustedIssuer struct {
	Id           string        `json:"id"`
	Capabilities *[]Capability `json:"capabilities"`
}

type Capability struct {
	ValidFor        *TimeRange   `json:"validFor,omitempty"`
	CredentialsType string       `json:"credentialsType,omitempty"`
	Claims          *[]Claim     `json:"claims,omitempty"`
	Policy          *interface{} `json:"policy,omitempty"`
}

type TimeRange struct {
	From string `json:"from,omitempty"`
	To   string `json:"to,omitempty"`
}

type Claim struct {
	Name          string          `json:"name"`
	AllowedValues *[]AllowedValue `json:"AllowedValues"`
}

type ProblemDetails struct {
	Type     string `json:"type"`
	Title    string `json:"title"`
	Status   int    `json:"status"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

type AllowedValue struct {
	Union json.RawMessage
}

type RoleValue struct {
	Name       *[]string `json:"name,omitempty"`
	ProviderId string    `json:"providerId,omitempty"`
}

type StringValue = string
type BooleanValue = bool
type NumberValue = int64

func (t *AllowedValue) AsAllowedValuesStringValue() (StringValue, error) {
	var body StringValue
	err := json.Unmarshal(t.Union, &body)
	return body, err
}

func (t *AllowedValue) FromClaimAllowedValuesStringValue(v StringValue) error {
	b, err := json.Marshal(v)
	t.Union = b
	return err
}

func (t *AllowedValue) MergeClaimAllowedValuesStringValue(v StringValue) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.Union)
	t.Union = merged
	return err
}

func (t *AllowedValue) AsAllowedValuesBooleanValue() (BooleanValue, error) {
	var body BooleanValue
	err := json.Unmarshal(t.Union, &body)
	return body, err
}

func (t *AllowedValue) FromClaimAllowedValuesBooleanValue(v BooleanValue) error {
	b, err := json.Marshal(v)
	t.Union = b
	return err
}

func (t *AllowedValue) MergeClaimAllowedValuesBooleanValue(v BooleanValue) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.Union)
	t.Union = merged
	return err
}

func (t *AllowedValue) AsAllowedValuesNumberValue() (NumberValue, error) {
	var body NumberValue
	err := json.Unmarshal(t.Union, &body)
	return body, err
}

func (t *AllowedValue) FromClaimAllowedValuesNumberValue(v NumberValue) error {
	b, err := json.Marshal(v)
	t.Union = b
	return err
}

func (t *AllowedValue) MergeClaimAllowedValuesNumberValue(v NumberValue) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.Union)
	t.Union = merged
	return err
}

func (t *AllowedValue) AsAllowedValuesRoleValue() (RoleValue, error) {
	var body RoleValue
	err := json.Unmarshal(t.Union, &body)
	return body, err
}

func (t *AllowedValue) FromClaimAllowedValuesRoleValue(v RoleValue) error {
	b, err := json.Marshal(v)
	t.Union = b
	return err
}

func (t *AllowedValue) MergeClaimAllowedValuesRoleValue(v RoleValue) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}

	merged, err := runtime.JsonMerge(b, t.Union)
	t.Union = merged
	return err
}

func (t AllowedValue) MarshalJSON() ([]byte, error) {
	b, err := t.Union.MarshalJSON()
	return b, err
}

func (t *AllowedValue) UnmarshalJSON(b []byte) error {
	err := t.Union.UnmarshalJSON(b)
	return err
}
