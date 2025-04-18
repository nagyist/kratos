/*
Ory Identities API

This is the API specification for Ory Identities with features such as registration, login, recovery, account verification, profile settings, password reset, identity management, session management, email and sms delivery, and more.

API version:
Contact: office@ory.sh
*/

// Code generated by OpenAPI Generator (https://openapi-generator.tech); DO NOT EDIT.

package client

import (
	"encoding/json"
)

// checks if the TokenPagination type satisfies the MappedNullable interface at compile time
var _ MappedNullable = &TokenPagination{}

// TokenPagination struct for TokenPagination
type TokenPagination struct {
	// Items per page  This is the number of items per page to return. For details on pagination please head over to the [pagination documentation](https://www.ory.sh/docs/ecosystem/api-design#pagination).
	PageSize *int64 `json:"page_size,omitempty"`
	// Next Page Token  The next page token. For details on pagination please head over to the [pagination documentation](https://www.ory.sh/docs/ecosystem/api-design#pagination).
	PageToken            *string `json:"page_token,omitempty"`
	AdditionalProperties map[string]interface{}
}

type _TokenPagination TokenPagination

// NewTokenPagination instantiates a new TokenPagination object
// This constructor will assign default values to properties that have it defined,
// and makes sure properties required by API are set, but the set of arguments
// will change when the set of required properties is changed
func NewTokenPagination() *TokenPagination {
	this := TokenPagination{}
	var pageSize int64 = 250
	this.PageSize = &pageSize
	var pageToken string = "1"
	this.PageToken = &pageToken
	return &this
}

// NewTokenPaginationWithDefaults instantiates a new TokenPagination object
// This constructor will only assign default values to properties that have it defined,
// but it doesn't guarantee that properties required by API are set
func NewTokenPaginationWithDefaults() *TokenPagination {
	this := TokenPagination{}
	var pageSize int64 = 250
	this.PageSize = &pageSize
	var pageToken string = "1"
	this.PageToken = &pageToken
	return &this
}

// GetPageSize returns the PageSize field value if set, zero value otherwise.
func (o *TokenPagination) GetPageSize() int64 {
	if o == nil || IsNil(o.PageSize) {
		var ret int64
		return ret
	}
	return *o.PageSize
}

// GetPageSizeOk returns a tuple with the PageSize field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TokenPagination) GetPageSizeOk() (*int64, bool) {
	if o == nil || IsNil(o.PageSize) {
		return nil, false
	}
	return o.PageSize, true
}

// HasPageSize returns a boolean if a field has been set.
func (o *TokenPagination) HasPageSize() bool {
	if o != nil && !IsNil(o.PageSize) {
		return true
	}

	return false
}

// SetPageSize gets a reference to the given int64 and assigns it to the PageSize field.
func (o *TokenPagination) SetPageSize(v int64) {
	o.PageSize = &v
}

// GetPageToken returns the PageToken field value if set, zero value otherwise.
func (o *TokenPagination) GetPageToken() string {
	if o == nil || IsNil(o.PageToken) {
		var ret string
		return ret
	}
	return *o.PageToken
}

// GetPageTokenOk returns a tuple with the PageToken field value if set, nil otherwise
// and a boolean to check if the value has been set.
func (o *TokenPagination) GetPageTokenOk() (*string, bool) {
	if o == nil || IsNil(o.PageToken) {
		return nil, false
	}
	return o.PageToken, true
}

// HasPageToken returns a boolean if a field has been set.
func (o *TokenPagination) HasPageToken() bool {
	if o != nil && !IsNil(o.PageToken) {
		return true
	}

	return false
}

// SetPageToken gets a reference to the given string and assigns it to the PageToken field.
func (o *TokenPagination) SetPageToken(v string) {
	o.PageToken = &v
}

func (o TokenPagination) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o TokenPagination) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	if !IsNil(o.PageSize) {
		toSerialize["page_size"] = o.PageSize
	}
	if !IsNil(o.PageToken) {
		toSerialize["page_token"] = o.PageToken
	}

	for key, value := range o.AdditionalProperties {
		toSerialize[key] = value
	}

	return toSerialize, nil
}

func (o *TokenPagination) UnmarshalJSON(data []byte) (err error) {
	varTokenPagination := _TokenPagination{}

	err = json.Unmarshal(data, &varTokenPagination)

	if err != nil {
		return err
	}

	*o = TokenPagination(varTokenPagination)

	additionalProperties := make(map[string]interface{})

	if err = json.Unmarshal(data, &additionalProperties); err == nil {
		delete(additionalProperties, "page_size")
		delete(additionalProperties, "page_token")
		o.AdditionalProperties = additionalProperties
	}

	return err
}

type NullableTokenPagination struct {
	value *TokenPagination
	isSet bool
}

func (v NullableTokenPagination) Get() *TokenPagination {
	return v.value
}

func (v *NullableTokenPagination) Set(val *TokenPagination) {
	v.value = val
	v.isSet = true
}

func (v NullableTokenPagination) IsSet() bool {
	return v.isSet
}

func (v *NullableTokenPagination) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableTokenPagination(val *TokenPagination) *NullableTokenPagination {
	return &NullableTokenPagination{value: val, isSet: true}
}

func (v NullableTokenPagination) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableTokenPagination) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
