// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package testhelpers

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"

	"github.com/ory/kratos/x/nosurfx"

	"github.com/ory/kratos/ui/node"

	"github.com/ory/x/pointerx"

	kratos "github.com/ory/kratos/internal/httpclient"
)

func NewSDKClient(ts *httptest.Server) *kratos.APIClient {
	return NewSDKClientFromURL(ts.URL)
}

func NewSDKCustomClient(ts *httptest.Server, client *http.Client) *kratos.APIClient {
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: ts.URL}}
	conf.HTTPClient = client
	return kratos.NewAPIClient(conf)
}

func NewSDKClientFromURL(u string) *kratos.APIClient {
	conf := kratos.NewConfiguration()
	conf.Servers = kratos.ServerConfigurations{{URL: u}}
	return kratos.NewAPIClient(conf)
}

func SDKFormFieldsToURLValues(ff []kratos.UiNode) url.Values {
	values := url.Values{}
	for _, f := range ff {
		attr := f.Attributes.UiNodeInputAttributes
		if attr == nil {
			continue
		}

		val := attr.Value
		if val == nil {
			continue
		}

		switch v := val.(type) {
		case bool:
			values.Set(attr.Name, fmt.Sprintf("%v", v))
		case string:
			values.Set(attr.Name, fmt.Sprintf("%v", v))
		case float32:
			values.Set(attr.Name, fmt.Sprintf("%v", v))
		case float64:
			values.Set(attr.Name, fmt.Sprintf("%v", v))
		}
	}
	return values
}

func NewFakeCSRFNode() *kratos.UiNode {
	return &kratos.UiNode{
		Group: node.DefaultGroup.String(),
		Type:  "input",
		Attributes: kratos.UiNodeInputAttributesAsUiNodeAttributes(&kratos.UiNodeInputAttributes{
			Name:     "csrf_token",
			Required: pointerx.Bool(true),
			Type:     "hidden",
			Value:    nosurfx.FakeCSRFToken,
		}),
	}
}

func NewSDKEmailNode(group string) *kratos.UiNode {
	return &kratos.UiNode{
		Type:  "input",
		Group: group,
		Attributes: kratos.UiNodeInputAttributesAsUiNodeAttributes(&kratos.UiNodeInputAttributes{
			Name:     "email",
			Type:     "email",
			Required: pointerx.Bool(true),
			Value:    "email",
		}),
	}
}

func NewMethodSubmit(group, value string) *kratos.UiNode {
	return &kratos.UiNode{
		Type:  "input",
		Group: group,
		Attributes: kratos.UiNodeInputAttributesAsUiNodeAttributes(&kratos.UiNodeInputAttributes{
			Name:  "method",
			Type:  "submit",
			Value: value,
		}),
	}
}

func NewPasswordNode() *kratos.UiNode {
	return &kratos.UiNode{
		Type:  "input",
		Group: node.PasswordGroup.String(),
		Attributes: kratos.UiNodeInputAttributesAsUiNodeAttributes(&kratos.UiNodeInputAttributes{
			Name:     "password",
			Type:     "password",
			Required: pointerx.Bool(true),
		}),
	}
}
