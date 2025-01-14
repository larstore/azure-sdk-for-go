//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armdeploymentmanager

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
	"strconv"
	"strings"
)

// RolloutsClient contains the methods for the Rollouts group.
// Don't use this type directly, use NewRolloutsClient() instead.
type RolloutsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewRolloutsClient creates a new instance of RolloutsClient with the specified values.
func NewRolloutsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *RolloutsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &RolloutsClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Cancel - Only running rollouts can be canceled.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) Cancel(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsCancelOptions) (RolloutsCancelResponse, error) {
	req, err := client.cancelCreateRequest(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return RolloutsCancelResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RolloutsCancelResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RolloutsCancelResponse{}, client.cancelHandleError(resp)
	}
	return client.cancelHandleResponse(resp)
}

// cancelCreateRequest creates the Cancel request.
func (client *RolloutsClient) cancelCreateRequest(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsCancelOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts/{rolloutName}/cancel"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if rolloutName == "" {
		return nil, errors.New("parameter rolloutName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{rolloutName}", url.PathEscape(rolloutName))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// cancelHandleResponse handles the Cancel response.
func (client *RolloutsClient) cancelHandleResponse(resp *http.Response) (RolloutsCancelResponse, error) {
	result := RolloutsCancelResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Rollout); err != nil {
		return RolloutsCancelResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// cancelHandleError handles the Cancel error response.
func (client *RolloutsClient) cancelHandleError(resp *http.Response) error {
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

// BeginCreateOrUpdate - This is an asynchronous operation and can be polled to completion using the location header returned by this operation.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsBeginCreateOrUpdateOptions) (RolloutsCreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return RolloutsCreateOrUpdatePollerResponse{}, err
	}
	result := RolloutsCreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("RolloutsClient.CreateOrUpdate", "", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return RolloutsCreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &RolloutsCreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - This is an asynchronous operation and can be polled to completion using the location header returned by this operation.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) createOrUpdate(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusCreated) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *RolloutsClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts/{rolloutName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if rolloutName == "" {
		return nil, errors.New("parameter rolloutName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{rolloutName}", url.PathEscape(rolloutName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	if options != nil && options.RolloutRequest != nil {
		return req, runtime.MarshalAsJSON(req, *options.RolloutRequest)
	}
	return req, nil
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *RolloutsClient) createOrUpdateHandleError(resp *http.Response) error {
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

// Delete - Only rollouts in terminal state can be deleted.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) Delete(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsDeleteOptions) (RolloutsDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return RolloutsDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RolloutsDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return RolloutsDeleteResponse{}, client.deleteHandleError(resp)
	}
	return RolloutsDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *RolloutsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts/{rolloutName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if rolloutName == "" {
		return nil, errors.New("parameter rolloutName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{rolloutName}", url.PathEscape(rolloutName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *RolloutsClient) deleteHandleError(resp *http.Response) error {
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

// Get - Gets detailed information of a rollout.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) Get(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsGetOptions) (RolloutsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return RolloutsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RolloutsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RolloutsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *RolloutsClient) getCreateRequest(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts/{rolloutName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if rolloutName == "" {
		return nil, errors.New("parameter rolloutName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{rolloutName}", url.PathEscape(rolloutName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-11-01-preview")
	if options != nil && options.RetryAttempt != nil {
		reqQP.Set("retryAttempt", strconv.FormatInt(int64(*options.RetryAttempt), 10))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *RolloutsClient) getHandleResponse(resp *http.Response) (RolloutsGetResponse, error) {
	result := RolloutsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Rollout); err != nil {
		return RolloutsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *RolloutsClient) getHandleError(resp *http.Response) error {
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

// List - Lists the rollouts in a resource group.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) List(ctx context.Context, resourceGroupName string, options *RolloutsListOptions) (RolloutsListResponse, error) {
	req, err := client.listCreateRequest(ctx, resourceGroupName, options)
	if err != nil {
		return RolloutsListResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RolloutsListResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RolloutsListResponse{}, client.listHandleError(resp)
	}
	return client.listHandleResponse(resp)
}

// listCreateRequest creates the List request.
func (client *RolloutsClient) listCreateRequest(ctx context.Context, resourceGroupName string, options *RolloutsListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts"
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
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *RolloutsClient) listHandleResponse(resp *http.Response) (RolloutsListResponse, error) {
	result := RolloutsListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.RolloutArray); err != nil {
		return RolloutsListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *RolloutsClient) listHandleError(resp *http.Response) error {
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

// Restart - Only failed rollouts can be restarted.
// If the operation fails it returns the *CloudError error type.
func (client *RolloutsClient) Restart(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsRestartOptions) (RolloutsRestartResponse, error) {
	req, err := client.restartCreateRequest(ctx, resourceGroupName, rolloutName, options)
	if err != nil {
		return RolloutsRestartResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return RolloutsRestartResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return RolloutsRestartResponse{}, client.restartHandleError(resp)
	}
	return client.restartHandleResponse(resp)
}

// restartCreateRequest creates the Restart request.
func (client *RolloutsClient) restartCreateRequest(ctx context.Context, resourceGroupName string, rolloutName string, options *RolloutsRestartOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DeploymentManager/rollouts/{rolloutName}/restart"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if rolloutName == "" {
		return nil, errors.New("parameter rolloutName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{rolloutName}", url.PathEscape(rolloutName))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.SkipSucceeded != nil {
		reqQP.Set("skipSucceeded", strconv.FormatBool(*options.SkipSucceeded))
	}
	reqQP.Set("api-version", "2019-11-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// restartHandleResponse handles the Restart response.
func (client *RolloutsClient) restartHandleResponse(resp *http.Response) (RolloutsRestartResponse, error) {
	result := RolloutsRestartResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Rollout); err != nil {
		return RolloutsRestartResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// restartHandleError handles the Restart error response.
func (client *RolloutsClient) restartHandleError(resp *http.Response) error {
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
