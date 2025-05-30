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
	"fmt"
)

// UpdateRecoveryFlowBody - Update Recovery Flow Request Body
type UpdateRecoveryFlowBody struct {
	UpdateRecoveryFlowWithCodeMethod *UpdateRecoveryFlowWithCodeMethod
	UpdateRecoveryFlowWithLinkMethod *UpdateRecoveryFlowWithLinkMethod
}

// UpdateRecoveryFlowWithCodeMethodAsUpdateRecoveryFlowBody is a convenience function that returns UpdateRecoveryFlowWithCodeMethod wrapped in UpdateRecoveryFlowBody
func UpdateRecoveryFlowWithCodeMethodAsUpdateRecoveryFlowBody(v *UpdateRecoveryFlowWithCodeMethod) UpdateRecoveryFlowBody {
	return UpdateRecoveryFlowBody{
		UpdateRecoveryFlowWithCodeMethod: v,
	}
}

// UpdateRecoveryFlowWithLinkMethodAsUpdateRecoveryFlowBody is a convenience function that returns UpdateRecoveryFlowWithLinkMethod wrapped in UpdateRecoveryFlowBody
func UpdateRecoveryFlowWithLinkMethodAsUpdateRecoveryFlowBody(v *UpdateRecoveryFlowWithLinkMethod) UpdateRecoveryFlowBody {
	return UpdateRecoveryFlowBody{
		UpdateRecoveryFlowWithLinkMethod: v,
	}
}

// Unmarshal JSON data into one of the pointers in the struct
func (dst *UpdateRecoveryFlowBody) UnmarshalJSON(data []byte) error {
	var err error
	// use discriminator value to speed up the lookup
	var jsonDict map[string]interface{}
	err = newStrictDecoder(data).Decode(&jsonDict)
	if err != nil {
		return fmt.Errorf("failed to unmarshal JSON into map for the discriminator lookup")
	}

	// check if the discriminator value is 'code'
	if jsonDict["method"] == "code" {
		// try to unmarshal JSON data into UpdateRecoveryFlowWithCodeMethod
		err = json.Unmarshal(data, &dst.UpdateRecoveryFlowWithCodeMethod)
		if err == nil {
			return nil // data stored in dst.UpdateRecoveryFlowWithCodeMethod, return on the first match
		} else {
			dst.UpdateRecoveryFlowWithCodeMethod = nil
			return fmt.Errorf("failed to unmarshal UpdateRecoveryFlowBody as UpdateRecoveryFlowWithCodeMethod: %s", err.Error())
		}
	}

	// check if the discriminator value is 'link'
	if jsonDict["method"] == "link" {
		// try to unmarshal JSON data into UpdateRecoveryFlowWithLinkMethod
		err = json.Unmarshal(data, &dst.UpdateRecoveryFlowWithLinkMethod)
		if err == nil {
			return nil // data stored in dst.UpdateRecoveryFlowWithLinkMethod, return on the first match
		} else {
			dst.UpdateRecoveryFlowWithLinkMethod = nil
			return fmt.Errorf("failed to unmarshal UpdateRecoveryFlowBody as UpdateRecoveryFlowWithLinkMethod: %s", err.Error())
		}
	}

	// check if the discriminator value is 'updateRecoveryFlowWithCodeMethod'
	if jsonDict["method"] == "updateRecoveryFlowWithCodeMethod" {
		// try to unmarshal JSON data into UpdateRecoveryFlowWithCodeMethod
		err = json.Unmarshal(data, &dst.UpdateRecoveryFlowWithCodeMethod)
		if err == nil {
			return nil // data stored in dst.UpdateRecoveryFlowWithCodeMethod, return on the first match
		} else {
			dst.UpdateRecoveryFlowWithCodeMethod = nil
			return fmt.Errorf("failed to unmarshal UpdateRecoveryFlowBody as UpdateRecoveryFlowWithCodeMethod: %s", err.Error())
		}
	}

	// check if the discriminator value is 'updateRecoveryFlowWithLinkMethod'
	if jsonDict["method"] == "updateRecoveryFlowWithLinkMethod" {
		// try to unmarshal JSON data into UpdateRecoveryFlowWithLinkMethod
		err = json.Unmarshal(data, &dst.UpdateRecoveryFlowWithLinkMethod)
		if err == nil {
			return nil // data stored in dst.UpdateRecoveryFlowWithLinkMethod, return on the first match
		} else {
			dst.UpdateRecoveryFlowWithLinkMethod = nil
			return fmt.Errorf("failed to unmarshal UpdateRecoveryFlowBody as UpdateRecoveryFlowWithLinkMethod: %s", err.Error())
		}
	}

	return nil
}

// Marshal data from the first non-nil pointers in the struct to JSON
func (src UpdateRecoveryFlowBody) MarshalJSON() ([]byte, error) {
	if src.UpdateRecoveryFlowWithCodeMethod != nil {
		return json.Marshal(&src.UpdateRecoveryFlowWithCodeMethod)
	}

	if src.UpdateRecoveryFlowWithLinkMethod != nil {
		return json.Marshal(&src.UpdateRecoveryFlowWithLinkMethod)
	}

	return nil, nil // no data in oneOf schemas
}

// Get the actual instance
func (obj *UpdateRecoveryFlowBody) GetActualInstance() interface{} {
	if obj == nil {
		return nil
	}
	if obj.UpdateRecoveryFlowWithCodeMethod != nil {
		return obj.UpdateRecoveryFlowWithCodeMethod
	}

	if obj.UpdateRecoveryFlowWithLinkMethod != nil {
		return obj.UpdateRecoveryFlowWithLinkMethod
	}

	// all schemas are nil
	return nil
}

// Get the actual instance value
func (obj UpdateRecoveryFlowBody) GetActualInstanceValue() interface{} {
	if obj.UpdateRecoveryFlowWithCodeMethod != nil {
		return *obj.UpdateRecoveryFlowWithCodeMethod
	}

	if obj.UpdateRecoveryFlowWithLinkMethod != nil {
		return *obj.UpdateRecoveryFlowWithLinkMethod
	}

	// all schemas are nil
	return nil
}

type NullableUpdateRecoveryFlowBody struct {
	value *UpdateRecoveryFlowBody
	isSet bool
}

func (v NullableUpdateRecoveryFlowBody) Get() *UpdateRecoveryFlowBody {
	return v.value
}

func (v *NullableUpdateRecoveryFlowBody) Set(val *UpdateRecoveryFlowBody) {
	v.value = val
	v.isSet = true
}

func (v NullableUpdateRecoveryFlowBody) IsSet() bool {
	return v.isSet
}

func (v *NullableUpdateRecoveryFlowBody) Unset() {
	v.value = nil
	v.isSet = false
}

func NewNullableUpdateRecoveryFlowBody(val *UpdateRecoveryFlowBody) *NullableUpdateRecoveryFlowBody {
	return &NullableUpdateRecoveryFlowBody{value: val, isSet: true}
}

func (v NullableUpdateRecoveryFlowBody) MarshalJSON() ([]byte, error) {
	return json.Marshal(v.value)
}

func (v *NullableUpdateRecoveryFlowBody) UnmarshalJSON(src []byte) error {
	v.isSet = true
	return json.Unmarshal(src, &v.value)
}
