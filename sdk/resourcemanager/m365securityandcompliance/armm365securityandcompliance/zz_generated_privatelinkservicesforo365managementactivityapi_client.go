//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armm365securityandcompliance

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

// PrivateLinkServicesForO365ManagementActivityAPIClient contains the methods for the PrivateLinkServicesForO365ManagementActivityAPI group.
// Don't use this type directly, use NewPrivateLinkServicesForO365ManagementActivityAPIClient() instead.
type PrivateLinkServicesForO365ManagementActivityAPIClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewPrivateLinkServicesForO365ManagementActivityAPIClient creates a new instance of PrivateLinkServicesForO365ManagementActivityAPIClient with the specified values.
func NewPrivateLinkServicesForO365ManagementActivityAPIClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *PrivateLinkServicesForO365ManagementActivityAPIClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &PrivateLinkServicesForO365ManagementActivityAPIClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreateOrUpdate - Create or update the metadata of a privateLinkServicesForO365ManagementActivityAPI instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, privateLinkServicesForO365ManagementActivityAPIDescription PrivateLinkServicesForO365ManagementActivityAPIDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginCreateOrUpdateOptions) (PrivateLinkServicesForO365ManagementActivityAPICreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, resourceGroupName, resourceName, privateLinkServicesForO365ManagementActivityAPIDescription, options)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPICreateOrUpdatePollerResponse{}, err
	}
	result := PrivateLinkServicesForO365ManagementActivityAPICreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("PrivateLinkServicesForO365ManagementActivityAPIClient.CreateOrUpdate", "location", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPICreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &PrivateLinkServicesForO365ManagementActivityAPICreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - Create or update the metadata of a privateLinkServicesForO365ManagementActivityAPI instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) createOrUpdate(ctx context.Context, resourceGroupName string, resourceName string, privateLinkServicesForO365ManagementActivityAPIDescription PrivateLinkServicesForO365ManagementActivityAPIDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, resourceName, privateLinkServicesForO365ManagementActivityAPIDescription, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, privateLinkServicesForO365ManagementActivityAPIDescription PrivateLinkServicesForO365ManagementActivityAPIDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, privateLinkServicesForO365ManagementActivityAPIDescription)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) createOrUpdateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// BeginDelete - Delete a service instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) BeginDelete(ctx context.Context, resourceGroupName string, resourceName string, options *PrivateLinkServicesForO365ManagementActivityAPIBeginDeleteOptions) (PrivateLinkServicesForO365ManagementActivityAPIDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIDeletePollerResponse{}, err
	}
	result := PrivateLinkServicesForO365ManagementActivityAPIDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("PrivateLinkServicesForO365ManagementActivityAPIClient.Delete", "location", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIDeletePollerResponse{}, err
	}
	result.Poller = &PrivateLinkServicesForO365ManagementActivityAPIDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Delete a service instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) deleteOperation(ctx context.Context, resourceGroupName string, resourceName string, options *PrivateLinkServicesForO365ManagementActivityAPIBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted, http.StatusNoContent) {
		return nil, client.deleteHandleError(resp)
	}
	return resp, nil
}

// deleteCreateRequest creates the Delete request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, options *PrivateLinkServicesForO365ManagementActivityAPIBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) deleteHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Get - Get the metadata of a privateLinkServicesForO365ManagementActivityAPI resource.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) Get(ctx context.Context, resourceGroupName string, resourceName string, options *PrivateLinkServicesForO365ManagementActivityAPIGetOptions) (PrivateLinkServicesForO365ManagementActivityAPIGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, resourceName, options)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return PrivateLinkServicesForO365ManagementActivityAPIGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) getCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, options *PrivateLinkServicesForO365ManagementActivityAPIGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) getHandleResponse(resp *http.Response) (PrivateLinkServicesForO365ManagementActivityAPIGetResponse, error) {
	result := PrivateLinkServicesForO365ManagementActivityAPIGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.PrivateLinkServicesForO365ManagementActivityAPIDescription); err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// List - Get all the privateLinkServicesForO365ManagementActivityAPI instances in a subscription.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) List(options *PrivateLinkServicesForO365ManagementActivityAPIListOptions) *PrivateLinkServicesForO365ManagementActivityAPIListPager {
	return &PrivateLinkServicesForO365ManagementActivityAPIListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp PrivateLinkServicesForO365ManagementActivityAPIListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.PrivateLinkServicesForO365ManagementActivityAPIDescriptionListResult.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listCreateRequest(ctx context.Context, options *PrivateLinkServicesForO365ManagementActivityAPIListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listHandleResponse(resp *http.Response) (PrivateLinkServicesForO365ManagementActivityAPIListResponse, error) {
	result := PrivateLinkServicesForO365ManagementActivityAPIListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.PrivateLinkServicesForO365ManagementActivityAPIDescriptionListResult); err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListByResourceGroup - Get all the service instances in a resource group.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) ListByResourceGroup(resourceGroupName string, options *PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupOptions) *PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupPager {
	return &PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.PrivateLinkServicesForO365ManagementActivityAPIDescriptionListResult.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI"
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
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listByResourceGroupHandleResponse(resp *http.Response) (PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupResponse, error) {
	result := PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.PrivateLinkServicesForO365ManagementActivityAPIDescriptionListResult); err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) listByResourceGroupHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// BeginUpdate - Update the metadata of a privateLinkServicesForO365ManagementActivityAPI instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) BeginUpdate(ctx context.Context, resourceGroupName string, resourceName string, servicePatchDescription ServicesPatchDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginUpdateOptions) (PrivateLinkServicesForO365ManagementActivityAPIUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, resourceName, servicePatchDescription, options)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIUpdatePollerResponse{}, err
	}
	result := PrivateLinkServicesForO365ManagementActivityAPIUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("PrivateLinkServicesForO365ManagementActivityAPIClient.Update", "location", resp, client.pl, client.updateHandleError)
	if err != nil {
		return PrivateLinkServicesForO365ManagementActivityAPIUpdatePollerResponse{}, err
	}
	result.Poller = &PrivateLinkServicesForO365ManagementActivityAPIUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Update the metadata of a privateLinkServicesForO365ManagementActivityAPI instance.
// If the operation fails it returns the *ErrorDetails error type.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) update(ctx context.Context, resourceGroupName string, resourceName string, servicePatchDescription ServicesPatchDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, resourceName, servicePatchDescription, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, client.updateHandleError(resp)
	}
	return resp, nil
}

// updateCreateRequest creates the Update request.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) updateCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, servicePatchDescription ServicesPatchDescription, options *PrivateLinkServicesForO365ManagementActivityAPIBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.M365SecurityAndCompliance/privateLinkServicesForO365ManagementActivityAPI/{resourceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-25-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, servicePatchDescription)
}

// updateHandleError handles the Update error response.
func (client *PrivateLinkServicesForO365ManagementActivityAPIClient) updateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
