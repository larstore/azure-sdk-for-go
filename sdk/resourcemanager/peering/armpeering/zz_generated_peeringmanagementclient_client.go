//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armpeering

import (
	"context"
	"errors"
	"fmt"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// PeeringManagementClient contains the methods for the PeeringManagementClient group.
// Don't use this type directly, use NewPeeringManagementClient() instead.
type PeeringManagementClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewPeeringManagementClient creates a new instance of PeeringManagementClient with the specified values.
func NewPeeringManagementClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *PeeringManagementClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &PeeringManagementClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// CheckServiceProviderAvailability - Checks if the peering service provider is present within 1000 miles of customer's location
// If the operation fails it returns the *ErrorResponse error type.
func (client *PeeringManagementClient) CheckServiceProviderAvailability(ctx context.Context, checkServiceProviderAvailabilityInput CheckServiceProviderAvailabilityInput, options *PeeringManagementClientCheckServiceProviderAvailabilityOptions) (PeeringManagementClientCheckServiceProviderAvailabilityResponse, error) {
	req, err := client.checkServiceProviderAvailabilityCreateRequest(ctx, checkServiceProviderAvailabilityInput, options)
	if err != nil {
		return PeeringManagementClientCheckServiceProviderAvailabilityResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return PeeringManagementClientCheckServiceProviderAvailabilityResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return PeeringManagementClientCheckServiceProviderAvailabilityResponse{}, client.checkServiceProviderAvailabilityHandleError(resp)
	}
	return client.checkServiceProviderAvailabilityHandleResponse(resp)
}

// checkServiceProviderAvailabilityCreateRequest creates the CheckServiceProviderAvailability request.
func (client *PeeringManagementClient) checkServiceProviderAvailabilityCreateRequest(ctx context.Context, checkServiceProviderAvailabilityInput CheckServiceProviderAvailabilityInput, options *PeeringManagementClientCheckServiceProviderAvailabilityOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Peering/CheckServiceProviderAvailability"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-08-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, checkServiceProviderAvailabilityInput)
}

// checkServiceProviderAvailabilityHandleResponse handles the CheckServiceProviderAvailability response.
func (client *PeeringManagementClient) checkServiceProviderAvailabilityHandleResponse(resp *http.Response) (PeeringManagementClientCheckServiceProviderAvailabilityResponse, error) {
	result := PeeringManagementClientCheckServiceProviderAvailabilityResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Value); err != nil {
		return PeeringManagementClientCheckServiceProviderAvailabilityResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// checkServiceProviderAvailabilityHandleError handles the CheckServiceProviderAvailability error response.
func (client *PeeringManagementClient) checkServiceProviderAvailabilityHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
