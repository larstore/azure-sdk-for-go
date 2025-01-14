//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armbaremetalinfrastructure

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

// AzureBareMetalInstancesClient contains the methods for the AzureBareMetalInstances group.
// Don't use this type directly, use NewAzureBareMetalInstancesClient() instead.
type AzureBareMetalInstancesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewAzureBareMetalInstancesClient creates a new instance of AzureBareMetalInstancesClient with the specified values.
func NewAzureBareMetalInstancesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *AzureBareMetalInstancesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &AzureBareMetalInstancesClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Get - Gets an Azure BareMetal instance for the specified subscription, resource group, and instance name.
// If the operation fails it returns the *ErrorResponse error type.
func (client *AzureBareMetalInstancesClient) Get(ctx context.Context, resourceGroupName string, azureBareMetalInstanceName string, options *AzureBareMetalInstancesGetOptions) (AzureBareMetalInstancesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, azureBareMetalInstanceName, options)
	if err != nil {
		return AzureBareMetalInstancesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return AzureBareMetalInstancesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return AzureBareMetalInstancesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *AzureBareMetalInstancesClient) getCreateRequest(ctx context.Context, resourceGroupName string, azureBareMetalInstanceName string, options *AzureBareMetalInstancesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BareMetalInfrastructure/bareMetalInstances/{azureBareMetalInstanceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if azureBareMetalInstanceName == "" {
		return nil, errors.New("parameter azureBareMetalInstanceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{azureBareMetalInstanceName}", url.PathEscape(azureBareMetalInstanceName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-09")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *AzureBareMetalInstancesClient) getHandleResponse(resp *http.Response) (AzureBareMetalInstancesGetResponse, error) {
	result := AzureBareMetalInstancesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureBareMetalInstance); err != nil {
		return AzureBareMetalInstancesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *AzureBareMetalInstancesClient) getHandleError(resp *http.Response) error {
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

// ListByResourceGroup - Gets a list of AzureBareMetal instances in the specified subscription and resource group. The operations returns various properties
// of each Azure BareMetal instance.
// If the operation fails it returns the *ErrorResponse error type.
func (client *AzureBareMetalInstancesClient) ListByResourceGroup(resourceGroupName string, options *AzureBareMetalInstancesListByResourceGroupOptions) *AzureBareMetalInstancesListByResourceGroupPager {
	return &AzureBareMetalInstancesListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp AzureBareMetalInstancesListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.AzureBareMetalInstancesListResult.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *AzureBareMetalInstancesClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *AzureBareMetalInstancesListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BareMetalInfrastructure/bareMetalInstances"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-09")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *AzureBareMetalInstancesClient) listByResourceGroupHandleResponse(resp *http.Response) (AzureBareMetalInstancesListByResourceGroupResponse, error) {
	result := AzureBareMetalInstancesListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureBareMetalInstancesListResult); err != nil {
		return AzureBareMetalInstancesListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *AzureBareMetalInstancesClient) listByResourceGroupHandleError(resp *http.Response) error {
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

// ListBySubscription - Gets a list of AzureBareMetal instances in the specified subscription. The operations returns various properties of each Azure BareMetal
// instance.
// If the operation fails it returns the *ErrorResponse error type.
func (client *AzureBareMetalInstancesClient) ListBySubscription(options *AzureBareMetalInstancesListBySubscriptionOptions) *AzureBareMetalInstancesListBySubscriptionPager {
	return &AzureBareMetalInstancesListBySubscriptionPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listBySubscriptionCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp AzureBareMetalInstancesListBySubscriptionResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.AzureBareMetalInstancesListResult.NextLink)
		},
	}
}

// listBySubscriptionCreateRequest creates the ListBySubscription request.
func (client *AzureBareMetalInstancesClient) listBySubscriptionCreateRequest(ctx context.Context, options *AzureBareMetalInstancesListBySubscriptionOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.BareMetalInfrastructure/bareMetalInstances"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-09")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listBySubscriptionHandleResponse handles the ListBySubscription response.
func (client *AzureBareMetalInstancesClient) listBySubscriptionHandleResponse(resp *http.Response) (AzureBareMetalInstancesListBySubscriptionResponse, error) {
	result := AzureBareMetalInstancesListBySubscriptionResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureBareMetalInstancesListResult); err != nil {
		return AzureBareMetalInstancesListBySubscriptionResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listBySubscriptionHandleError handles the ListBySubscription error response.
func (client *AzureBareMetalInstancesClient) listBySubscriptionHandleError(resp *http.Response) error {
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

// Update - Patches the Tags field of a Azure BareMetal instance for the specified subscription, resource group, and instance name.
// If the operation fails it returns the *ErrorResponse error type.
func (client *AzureBareMetalInstancesClient) Update(ctx context.Context, resourceGroupName string, azureBareMetalInstanceName string, tagsParameter Tags, options *AzureBareMetalInstancesUpdateOptions) (AzureBareMetalInstancesUpdateResponse, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, azureBareMetalInstanceName, tagsParameter, options)
	if err != nil {
		return AzureBareMetalInstancesUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return AzureBareMetalInstancesUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return AzureBareMetalInstancesUpdateResponse{}, client.updateHandleError(resp)
	}
	return client.updateHandleResponse(resp)
}

// updateCreateRequest creates the Update request.
func (client *AzureBareMetalInstancesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, azureBareMetalInstanceName string, tagsParameter Tags, options *AzureBareMetalInstancesUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BareMetalInfrastructure/bareMetalInstances/{azureBareMetalInstanceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if azureBareMetalInstanceName == "" {
		return nil, errors.New("parameter azureBareMetalInstanceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{azureBareMetalInstanceName}", url.PathEscape(azureBareMetalInstanceName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-09")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, tagsParameter)
}

// updateHandleResponse handles the Update response.
func (client *AzureBareMetalInstancesClient) updateHandleResponse(resp *http.Response) (AzureBareMetalInstancesUpdateResponse, error) {
	result := AzureBareMetalInstancesUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AzureBareMetalInstance); err != nil {
		return AzureBareMetalInstancesUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// updateHandleError handles the Update error response.
func (client *AzureBareMetalInstancesClient) updateHandleError(resp *http.Response) error {
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
