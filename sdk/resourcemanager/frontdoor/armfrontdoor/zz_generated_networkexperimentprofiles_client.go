//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armfrontdoor

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

// NetworkExperimentProfilesClient contains the methods for the NetworkExperimentProfiles group.
// Don't use this type directly, use NewNetworkExperimentProfilesClient() instead.
type NetworkExperimentProfilesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewNetworkExperimentProfilesClient creates a new instance of NetworkExperimentProfilesClient with the specified values.
func NewNetworkExperimentProfilesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *NetworkExperimentProfilesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &NetworkExperimentProfilesClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreateOrUpdate - Creates an NetworkExperiment Profile
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) BeginCreateOrUpdate(ctx context.Context, profileName string, resourceGroupName string, parameters Profile, options *NetworkExperimentProfilesBeginCreateOrUpdateOptions) (NetworkExperimentProfilesCreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, profileName, resourceGroupName, parameters, options)
	if err != nil {
		return NetworkExperimentProfilesCreateOrUpdatePollerResponse{}, err
	}
	result := NetworkExperimentProfilesCreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("NetworkExperimentProfilesClient.CreateOrUpdate", "", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return NetworkExperimentProfilesCreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &NetworkExperimentProfilesCreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - Creates an NetworkExperiment Profile
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) createOrUpdate(ctx context.Context, profileName string, resourceGroupName string, parameters Profile, options *NetworkExperimentProfilesBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, profileName, resourceGroupName, parameters, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *NetworkExperimentProfilesClient) createOrUpdateCreateRequest(ctx context.Context, profileName string, resourceGroupName string, parameters Profile, options *NetworkExperimentProfilesBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}"
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *NetworkExperimentProfilesClient) createOrUpdateHandleError(resp *http.Response) error {
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

// BeginDelete - Deletes an NetworkExperiment Profile by ProfileName
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) BeginDelete(ctx context.Context, resourceGroupName string, profileName string, options *NetworkExperimentProfilesBeginDeleteOptions) (NetworkExperimentProfilesDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, profileName, options)
	if err != nil {
		return NetworkExperimentProfilesDeletePollerResponse{}, err
	}
	result := NetworkExperimentProfilesDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("NetworkExperimentProfilesClient.Delete", "", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return NetworkExperimentProfilesDeletePollerResponse{}, err
	}
	result.Poller = &NetworkExperimentProfilesDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes an NetworkExperiment Profile by ProfileName
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) deleteOperation(ctx context.Context, resourceGroupName string, profileName string, options *NetworkExperimentProfilesBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, profileName, options)
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
func (client *NetworkExperimentProfilesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, profileName string, options *NetworkExperimentProfilesBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *NetworkExperimentProfilesClient) deleteHandleError(resp *http.Response) error {
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

// Get - Gets an NetworkExperiment Profile by ProfileName
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) Get(ctx context.Context, resourceGroupName string, profileName string, options *NetworkExperimentProfilesGetOptions) (NetworkExperimentProfilesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, profileName, options)
	if err != nil {
		return NetworkExperimentProfilesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return NetworkExperimentProfilesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return NetworkExperimentProfilesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *NetworkExperimentProfilesClient) getCreateRequest(ctx context.Context, resourceGroupName string, profileName string, options *NetworkExperimentProfilesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *NetworkExperimentProfilesClient) getHandleResponse(resp *http.Response) (NetworkExperimentProfilesGetResponse, error) {
	result := NetworkExperimentProfilesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Profile); err != nil {
		return NetworkExperimentProfilesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *NetworkExperimentProfilesClient) getHandleError(resp *http.Response) error {
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

// List - Gets a list of Network Experiment Profiles under a subscription
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) List(options *NetworkExperimentProfilesListOptions) *NetworkExperimentProfilesListPager {
	return &NetworkExperimentProfilesListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp NetworkExperimentProfilesListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ProfileList.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *NetworkExperimentProfilesClient) listCreateRequest(ctx context.Context, options *NetworkExperimentProfilesListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Network/NetworkExperimentProfiles"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *NetworkExperimentProfilesClient) listHandleResponse(resp *http.Response) (NetworkExperimentProfilesListResponse, error) {
	result := NetworkExperimentProfilesListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ProfileList); err != nil {
		return NetworkExperimentProfilesListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *NetworkExperimentProfilesClient) listHandleError(resp *http.Response) error {
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

// ListByResourceGroup - Gets a list of Network Experiment Profiles within a resource group under a subscription
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) ListByResourceGroup(resourceGroupName string, options *NetworkExperimentProfilesListByResourceGroupOptions) *NetworkExperimentProfilesListByResourceGroupPager {
	return &NetworkExperimentProfilesListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp NetworkExperimentProfilesListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ProfileList.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *NetworkExperimentProfilesClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *NetworkExperimentProfilesListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles"
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
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *NetworkExperimentProfilesClient) listByResourceGroupHandleResponse(resp *http.Response) (NetworkExperimentProfilesListByResourceGroupResponse, error) {
	result := NetworkExperimentProfilesListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ProfileList); err != nil {
		return NetworkExperimentProfilesListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *NetworkExperimentProfilesClient) listByResourceGroupHandleError(resp *http.Response) error {
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

// BeginUpdate - Updates an NetworkExperimentProfiles
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) BeginUpdate(ctx context.Context, resourceGroupName string, profileName string, parameters ProfileUpdateModel, options *NetworkExperimentProfilesBeginUpdateOptions) (NetworkExperimentProfilesUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, profileName, parameters, options)
	if err != nil {
		return NetworkExperimentProfilesUpdatePollerResponse{}, err
	}
	result := NetworkExperimentProfilesUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("NetworkExperimentProfilesClient.Update", "", resp, client.pl, client.updateHandleError)
	if err != nil {
		return NetworkExperimentProfilesUpdatePollerResponse{}, err
	}
	result.Poller = &NetworkExperimentProfilesUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Updates an NetworkExperimentProfiles
// If the operation fails it returns the *ErrorResponse error type.
func (client *NetworkExperimentProfilesClient) update(ctx context.Context, resourceGroupName string, profileName string, parameters ProfileUpdateModel, options *NetworkExperimentProfilesBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, profileName, parameters, options)
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
func (client *NetworkExperimentProfilesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, profileName string, parameters ProfileUpdateModel, options *NetworkExperimentProfilesBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Network/NetworkExperimentProfiles/{profileName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if profileName == "" {
		return nil, errors.New("parameter profileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{profileName}", url.PathEscape(profileName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// updateHandleError handles the Update error response.
func (client *NetworkExperimentProfilesClient) updateHandleError(resp *http.Response) error {
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
