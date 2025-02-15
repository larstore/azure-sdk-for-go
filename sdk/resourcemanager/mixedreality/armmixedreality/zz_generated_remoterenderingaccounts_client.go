//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmixedreality

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

// RemoteRenderingAccountsClient contains the methods for the RemoteRenderingAccounts group.
// Don't use this type directly, use NewRemoteRenderingAccountsClient() instead.
type RemoteRenderingAccountsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewRemoteRenderingAccountsClient creates a new instance of RemoteRenderingAccountsClient with the specified values.
func NewRemoteRenderingAccountsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *RemoteRenderingAccountsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &RemoteRenderingAccountsClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Create - Creating or Updating a Remote Rendering Account.
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) Create(ctx context.Context, resourceGroupName string, accountName string, remoteRenderingAccount RemoteRenderingAccount, options *RemoteRenderingAccountsCreateOptions) (RemoteRenderingAccountsCreateResponse, error) {
	req, err := client.createCreateRequest(ctx, resourceGroupName, accountName, remoteRenderingAccount, options)
	if err != nil {
		return RemoteRenderingAccountsCreateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsCreateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated) {
		return RemoteRenderingAccountsCreateResponse{}, client.createHandleError(resp)
	}
	return client.createHandleResponse(resp)
}

// createCreateRequest creates the Create request.
func (client *RemoteRenderingAccountsClient) createCreateRequest(ctx context.Context, resourceGroupName string, accountName string, remoteRenderingAccount RemoteRenderingAccount, options *RemoteRenderingAccountsCreateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, remoteRenderingAccount)
}

// createHandleResponse handles the Create response.
func (client *RemoteRenderingAccountsClient) createHandleResponse(resp *http.Response) (RemoteRenderingAccountsCreateResponse, error) {
	result := RemoteRenderingAccountsCreateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RemoteRenderingAccount); err != nil {
		return RemoteRenderingAccountsCreateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// createHandleError handles the Create error response.
func (client *RemoteRenderingAccountsClient) createHandleError(resp *http.Response) error {
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

// Delete - Delete a Remote Rendering Account.
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) Delete(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsDeleteOptions) (RemoteRenderingAccountsDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return RemoteRenderingAccountsDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return RemoteRenderingAccountsDeleteResponse{}, client.deleteHandleError(resp)
	}
	return RemoteRenderingAccountsDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *RemoteRenderingAccountsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *RemoteRenderingAccountsClient) deleteHandleError(resp *http.Response) error {
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

// Get - Retrieve a Remote Rendering Account.
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) Get(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsGetOptions) (RemoteRenderingAccountsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return RemoteRenderingAccountsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RemoteRenderingAccountsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *RemoteRenderingAccountsClient) getCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *RemoteRenderingAccountsClient) getHandleResponse(resp *http.Response) (RemoteRenderingAccountsGetResponse, error) {
	result := RemoteRenderingAccountsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RemoteRenderingAccount); err != nil {
		return RemoteRenderingAccountsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *RemoteRenderingAccountsClient) getHandleError(resp *http.Response) error {
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

// ListByResourceGroup - List Resources by Resource Group
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) ListByResourceGroup(resourceGroupName string, options *RemoteRenderingAccountsListByResourceGroupOptions) *RemoteRenderingAccountsListByResourceGroupPager {
	return &RemoteRenderingAccountsListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp RemoteRenderingAccountsListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.RemoteRenderingAccountPage.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *RemoteRenderingAccountsClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *RemoteRenderingAccountsListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts"
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
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *RemoteRenderingAccountsClient) listByResourceGroupHandleResponse(resp *http.Response) (RemoteRenderingAccountsListByResourceGroupResponse, error) {
	result := RemoteRenderingAccountsListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RemoteRenderingAccountPage); err != nil {
		return RemoteRenderingAccountsListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *RemoteRenderingAccountsClient) listByResourceGroupHandleError(resp *http.Response) error {
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

// ListBySubscription - List Remote Rendering Accounts by Subscription
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) ListBySubscription(options *RemoteRenderingAccountsListBySubscriptionOptions) *RemoteRenderingAccountsListBySubscriptionPager {
	return &RemoteRenderingAccountsListBySubscriptionPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listBySubscriptionCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp RemoteRenderingAccountsListBySubscriptionResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.RemoteRenderingAccountPage.NextLink)
		},
	}
}

// listBySubscriptionCreateRequest creates the ListBySubscription request.
func (client *RemoteRenderingAccountsClient) listBySubscriptionCreateRequest(ctx context.Context, options *RemoteRenderingAccountsListBySubscriptionOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.MixedReality/remoteRenderingAccounts"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listBySubscriptionHandleResponse handles the ListBySubscription response.
func (client *RemoteRenderingAccountsClient) listBySubscriptionHandleResponse(resp *http.Response) (RemoteRenderingAccountsListBySubscriptionResponse, error) {
	result := RemoteRenderingAccountsListBySubscriptionResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RemoteRenderingAccountPage); err != nil {
		return RemoteRenderingAccountsListBySubscriptionResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listBySubscriptionHandleError handles the ListBySubscription error response.
func (client *RemoteRenderingAccountsClient) listBySubscriptionHandleError(resp *http.Response) error {
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

// ListKeys - List Both of the 2 Keys of a Remote Rendering Account
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) ListKeys(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsListKeysOptions) (RemoteRenderingAccountsListKeysResponse, error) {
	req, err := client.listKeysCreateRequest(ctx, resourceGroupName, accountName, options)
	if err != nil {
		return RemoteRenderingAccountsListKeysResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsListKeysResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RemoteRenderingAccountsListKeysResponse{}, client.listKeysHandleError(resp)
	}
	return client.listKeysHandleResponse(resp)
}

// listKeysCreateRequest creates the ListKeys request.
func (client *RemoteRenderingAccountsClient) listKeysCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *RemoteRenderingAccountsListKeysOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}/listKeys"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listKeysHandleResponse handles the ListKeys response.
func (client *RemoteRenderingAccountsClient) listKeysHandleResponse(resp *http.Response) (RemoteRenderingAccountsListKeysResponse, error) {
	result := RemoteRenderingAccountsListKeysResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AccountKeys); err != nil {
		return RemoteRenderingAccountsListKeysResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listKeysHandleError handles the ListKeys error response.
func (client *RemoteRenderingAccountsClient) listKeysHandleError(resp *http.Response) error {
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

// RegenerateKeys - Regenerate specified Key of a Remote Rendering Account
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) RegenerateKeys(ctx context.Context, resourceGroupName string, accountName string, regenerate AccountKeyRegenerateRequest, options *RemoteRenderingAccountsRegenerateKeysOptions) (RemoteRenderingAccountsRegenerateKeysResponse, error) {
	req, err := client.regenerateKeysCreateRequest(ctx, resourceGroupName, accountName, regenerate, options)
	if err != nil {
		return RemoteRenderingAccountsRegenerateKeysResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsRegenerateKeysResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RemoteRenderingAccountsRegenerateKeysResponse{}, client.regenerateKeysHandleError(resp)
	}
	return client.regenerateKeysHandleResponse(resp)
}

// regenerateKeysCreateRequest creates the RegenerateKeys request.
func (client *RemoteRenderingAccountsClient) regenerateKeysCreateRequest(ctx context.Context, resourceGroupName string, accountName string, regenerate AccountKeyRegenerateRequest, options *RemoteRenderingAccountsRegenerateKeysOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}/regenerateKeys"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, regenerate)
}

// regenerateKeysHandleResponse handles the RegenerateKeys response.
func (client *RemoteRenderingAccountsClient) regenerateKeysHandleResponse(resp *http.Response) (RemoteRenderingAccountsRegenerateKeysResponse, error) {
	result := RemoteRenderingAccountsRegenerateKeysResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.AccountKeys); err != nil {
		return RemoteRenderingAccountsRegenerateKeysResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// regenerateKeysHandleError handles the RegenerateKeys error response.
func (client *RemoteRenderingAccountsClient) regenerateKeysHandleError(resp *http.Response) error {
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

// Update - Updating a Remote Rendering Account
// If the operation fails it returns the *CloudError error type.
func (client *RemoteRenderingAccountsClient) Update(ctx context.Context, resourceGroupName string, accountName string, remoteRenderingAccount RemoteRenderingAccount, options *RemoteRenderingAccountsUpdateOptions) (RemoteRenderingAccountsUpdateResponse, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, accountName, remoteRenderingAccount, options)
	if err != nil {
		return RemoteRenderingAccountsUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RemoteRenderingAccountsUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RemoteRenderingAccountsUpdateResponse{}, client.updateHandleError(resp)
	}
	return client.updateHandleResponse(resp)
}

// updateCreateRequest creates the Update request.
func (client *RemoteRenderingAccountsClient) updateCreateRequest(ctx context.Context, resourceGroupName string, accountName string, remoteRenderingAccount RemoteRenderingAccount, options *RemoteRenderingAccountsUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.MixedReality/remoteRenderingAccounts/{accountName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if accountName == "" {
		return nil, errors.New("parameter accountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{accountName}", url.PathEscape(accountName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, remoteRenderingAccount)
}

// updateHandleResponse handles the Update response.
func (client *RemoteRenderingAccountsClient) updateHandleResponse(resp *http.Response) (RemoteRenderingAccountsUpdateResponse, error) {
	result := RemoteRenderingAccountsUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RemoteRenderingAccount); err != nil {
		return RemoteRenderingAccountsUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// updateHandleError handles the Update error response.
func (client *RemoteRenderingAccountsClient) updateHandleError(resp *http.Response) error {
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
