//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armbatch

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

// BatchAccountClient contains the methods for the BatchAccount group.
// Don't use this type directly, use NewBatchAccountClient() instead.
type BatchAccountClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewBatchAccountClient creates a new instance of BatchAccountClient with the specified values.
func NewBatchAccountClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *BatchAccountClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &BatchAccountClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreate - Creates a new Batch account with the specified parameters. Existing accounts cannot be updated with this API and should instead be updated
// with the Update Batch Account API.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) BeginCreate(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountCreateParameters, options *BatchAccountBeginCreateOptions) (BatchAccountCreatePollerResponse, error) {
	resp, err := client.create(ctx, resourceGroupName, accountName, parameters, options)
	if err != nil {
		return BatchAccountCreatePollerResponse{}, err
	}
	result := BatchAccountCreatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("BatchAccountClient.Create", "location", resp, client.pl, client.createHandleError)
	if err != nil {
		return BatchAccountCreatePollerResponse{}, err
	}
	result.Poller = &BatchAccountCreatePoller{
		pt: pt,
	}
	return result, nil
}

// Create - Creates a new Batch account with the specified parameters. Existing accounts cannot be updated with this API and should instead be updated with
// the Update Batch Account API.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) create(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountCreateParameters, options *BatchAccountBeginCreateOptions) (*http.Response, error) {
	req, err := client.createCreateRequest(ctx, resourceGroupName, accountName, parameters, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, client.createHandleError(resp)
	}
	return resp, nil
}

// createCreateRequest creates the Create request.
func (client *BatchAccountClient) createCreateRequest(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountCreateParameters, options *BatchAccountBeginCreateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createHandleError handles the Create error response.
func (client *BatchAccountClient) createHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// BeginDelete - Deletes the specified Batch account.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) BeginDelete(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountBeginDeleteOptions) (BatchAccountDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return BatchAccountDeletePollerResponse{}, err
	}
	result := BatchAccountDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("BatchAccountClient.Delete", "location", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return BatchAccountDeletePollerResponse{}, err
	}
	result.Poller = &BatchAccountDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes the specified Batch account.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) deleteOperation(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, accountName, options)
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
func (client *BatchAccountClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *BatchAccountClient) deleteHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Get - Gets information about the specified Batch account.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) Get(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountGetOptions) (BatchAccountGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return BatchAccountGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return BatchAccountGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return BatchAccountGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *BatchAccountClient) getCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *BatchAccountClient) getHandleResponse(resp *http.Response) (BatchAccountGetResponse, error) {
	result := BatchAccountGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccount); err != nil {
		return BatchAccountGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *BatchAccountClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// GetKeys - This operation applies only to Batch accounts with allowedAuthenticationModes containing 'SharedKey'. If the Batch account doesn't contain
// 'SharedKey' in its allowedAuthenticationMode, clients cannot
// use shared keys to authenticate, and must use another allowedAuthenticationModes instead. In this case, getting the keys will fail.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) GetKeys(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountGetKeysOptions) (BatchAccountGetKeysResponse, error) {
	req, err := client.getKeysCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return BatchAccountGetKeysResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return BatchAccountGetKeysResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return BatchAccountGetKeysResponse{}, client.getKeysHandleError(resp)
	}
	return client.getKeysHandleResponse(resp)
}

// getKeysCreateRequest creates the GetKeys request.
func (client *BatchAccountClient) getKeysCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountGetKeysOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/listKeys"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getKeysHandleResponse handles the GetKeys response.
func (client *BatchAccountClient) getKeysHandleResponse(resp *http.Response) (BatchAccountGetKeysResponse, error) {
	result := BatchAccountGetKeysResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccountKeys); err != nil {
		return BatchAccountGetKeysResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getKeysHandleError handles the GetKeys error response.
func (client *BatchAccountClient) getKeysHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// List - Gets information about the Batch accounts associated with the subscription.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) List(options *BatchAccountListOptions) *BatchAccountListPager {
	return &BatchAccountListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp BatchAccountListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.BatchAccountListResult.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *BatchAccountClient) listCreateRequest(ctx context.Context, options *BatchAccountListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.Batch/batchAccounts"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *BatchAccountClient) listHandleResponse(resp *http.Response) (BatchAccountListResponse, error) {
	result := BatchAccountListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccountListResult); err != nil {
		return BatchAccountListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *BatchAccountClient) listHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListByResourceGroup - Gets information about the Batch accounts associated with the specified resource group.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) ListByResourceGroup(resourceGroupName string, options *BatchAccountListByResourceGroupOptions) *BatchAccountListByResourceGroupPager {
	return &BatchAccountListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp BatchAccountListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.BatchAccountListResult.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *BatchAccountClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *BatchAccountListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *BatchAccountClient) listByResourceGroupHandleResponse(resp *http.Response) (BatchAccountListByResourceGroupResponse, error) {
	result := BatchAccountListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccountListResult); err != nil {
		return BatchAccountListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *BatchAccountClient) listByResourceGroupHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListOutboundNetworkDependenciesEndpoints - Lists the endpoints that a Batch Compute Node under this Batch Account may call as part of Batch service administration.
// If you are deploying a Pool inside of a virtual network that you specify, you
// must make sure your network allows outbound access to these endpoints. Failure to allow access to these endpoints may cause Batch to mark the affected
// nodes as unusable. For more information about
// creating a pool inside of a virtual network, see https://docs.microsoft.com/en-us/azure/batch/batch-virtual-network.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) ListOutboundNetworkDependenciesEndpoints(resourceGroupName string, accountName string, options *BatchAccountListOutboundNetworkDependenciesEndpointsOptions) *BatchAccountListOutboundNetworkDependenciesEndpointsPager {
	return &BatchAccountListOutboundNetworkDependenciesEndpointsPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listOutboundNetworkDependenciesEndpointsCreateRequest(ctx, resourceGroupName, accountName, options)
		},
		advancer: func(ctx context.Context, resp BatchAccountListOutboundNetworkDependenciesEndpointsResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.OutboundEnvironmentEndpointCollection.NextLink)
		},
	}
}

// listOutboundNetworkDependenciesEndpointsCreateRequest creates the ListOutboundNetworkDependenciesEndpoints request.
func (client *BatchAccountClient) listOutboundNetworkDependenciesEndpointsCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountListOutboundNetworkDependenciesEndpointsOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/outboundNetworkDependenciesEndpoints"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listOutboundNetworkDependenciesEndpointsHandleResponse handles the ListOutboundNetworkDependenciesEndpoints response.
func (client *BatchAccountClient) listOutboundNetworkDependenciesEndpointsHandleResponse(resp *http.Response) (BatchAccountListOutboundNetworkDependenciesEndpointsResponse, error) {
	result := BatchAccountListOutboundNetworkDependenciesEndpointsResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.OutboundEnvironmentEndpointCollection); err != nil {
		return BatchAccountListOutboundNetworkDependenciesEndpointsResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listOutboundNetworkDependenciesEndpointsHandleError handles the ListOutboundNetworkDependenciesEndpoints error response.
func (client *BatchAccountClient) listOutboundNetworkDependenciesEndpointsHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// RegenerateKey - This operation applies only to Batch accounts with allowedAuthenticationModes containing 'SharedKey'. If the Batch account doesn't contain
// 'SharedKey' in its allowedAuthenticationMode, clients cannot
// use shared keys to authenticate, and must use another allowedAuthenticationModes instead. In this case, regenerating the keys will fail.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) RegenerateKey(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountRegenerateKeyParameters, options *BatchAccountRegenerateKeyOptions) (BatchAccountRegenerateKeyResponse, error) {
	req, err := client.regenerateKeyCreateRequest(ctx, resourceGroupName, accountName, parameters, options)
	if err != nil {
		return BatchAccountRegenerateKeyResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return BatchAccountRegenerateKeyResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return BatchAccountRegenerateKeyResponse{}, client.regenerateKeyHandleError(resp)
	}
	return client.regenerateKeyHandleResponse(resp)
}

// regenerateKeyCreateRequest creates the RegenerateKey request.
func (client *BatchAccountClient) regenerateKeyCreateRequest(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountRegenerateKeyParameters, options *BatchAccountRegenerateKeyOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/regenerateKeys"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// regenerateKeyHandleResponse handles the RegenerateKey response.
func (client *BatchAccountClient) regenerateKeyHandleResponse(resp *http.Response) (BatchAccountRegenerateKeyResponse, error) {
	result := BatchAccountRegenerateKeyResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccountKeys); err != nil {
		return BatchAccountRegenerateKeyResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// regenerateKeyHandleError handles the RegenerateKey error response.
func (client *BatchAccountClient) regenerateKeyHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// SynchronizeAutoStorageKeys - Synchronizes access keys for the auto-storage account configured for the specified Batch account, only if storage key authentication
// is being used.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) SynchronizeAutoStorageKeys(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountSynchronizeAutoStorageKeysOptions) (BatchAccountSynchronizeAutoStorageKeysResponse, error) {
	req, err := client.synchronizeAutoStorageKeysCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return BatchAccountSynchronizeAutoStorageKeysResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return BatchAccountSynchronizeAutoStorageKeysResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusNoContent) {
		return BatchAccountSynchronizeAutoStorageKeysResponse{}, client.synchronizeAutoStorageKeysHandleError(resp)
	}
	return BatchAccountSynchronizeAutoStorageKeysResponse{RawResponse: resp}, nil
}

// synchronizeAutoStorageKeysCreateRequest creates the SynchronizeAutoStorageKeys request.
func (client *BatchAccountClient) synchronizeAutoStorageKeysCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *BatchAccountSynchronizeAutoStorageKeysOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}/syncAutoStorageKeys"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// synchronizeAutoStorageKeysHandleError handles the SynchronizeAutoStorageKeys error response.
func (client *BatchAccountClient) synchronizeAutoStorageKeysHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Update - Updates the properties of an existing Batch account.
// If the operation fails it returns the *CloudError error type.
func (client *BatchAccountClient) Update(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountUpdateParameters, options *BatchAccountUpdateOptions) (BatchAccountUpdateResponse, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, accountName, parameters, options)
	if err != nil {
		return BatchAccountUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return BatchAccountUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return BatchAccountUpdateResponse{}, client.updateHandleError(resp)
	}
	return client.updateHandleResponse(resp)
}

// updateCreateRequest creates the Update request.
func (client *BatchAccountClient) updateCreateRequest(ctx context.Context, resourceGroupName string, accountName string, parameters BatchAccountUpdateParameters, options *BatchAccountUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Batch/batchAccounts/{accountName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// updateHandleResponse handles the Update response.
func (client *BatchAccountClient) updateHandleResponse(resp *http.Response) (BatchAccountUpdateResponse, error) {
	result := BatchAccountUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BatchAccount); err != nil {
		return BatchAccountUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// updateHandleError handles the Update error response.
func (client *BatchAccountClient) updateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CloudError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
