//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmediaservices

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

// StreamingEndpointsClient contains the methods for the StreamingEndpoints group.
// Don't use this type directly, use NewStreamingEndpointsClient() instead.
type StreamingEndpointsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewStreamingEndpointsClient creates a new instance of StreamingEndpointsClient with the specified values.
func NewStreamingEndpointsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *StreamingEndpointsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &StreamingEndpointsClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreate - Creates a streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginCreate(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginCreateOptions) (StreamingEndpointsCreatePollerResponse, error) {
	resp, err := client.create(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
	if err != nil {
		return StreamingEndpointsCreatePollerResponse{}, err
	}
	result := StreamingEndpointsCreatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Create", "", resp, client.pl, client.createHandleError)
	if err != nil {
		return StreamingEndpointsCreatePollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsCreatePoller{
		pt: pt,
	}
	return result, nil
}

// Create - Creates a streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) create(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginCreateOptions) (*http.Response, error) {
	req, err := client.createCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated) {
		return nil, client.createHandleError(resp)
	}
	return resp, nil
}

// createCreateRequest creates the Create request.
func (client *StreamingEndpointsClient) createCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginCreateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01")
	if options != nil && options.AutoStart != nil {
		reqQP.Set("autoStart", strconv.FormatBool(*options.AutoStart))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createHandleError handles the Create error response.
func (client *StreamingEndpointsClient) createHandleError(resp *http.Response) error {
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

// BeginDelete - Deletes a streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginDelete(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginDeleteOptions) (StreamingEndpointsDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return StreamingEndpointsDeletePollerResponse{}, err
	}
	result := StreamingEndpointsDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Delete", "", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return StreamingEndpointsDeletePollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes a streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) deleteOperation(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, options)
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
func (client *StreamingEndpointsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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
func (client *StreamingEndpointsClient) deleteHandleError(resp *http.Response) error {
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

// Get - Gets a streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) Get(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsGetOptions) (StreamingEndpointsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return StreamingEndpointsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return StreamingEndpointsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return StreamingEndpointsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *StreamingEndpointsClient) getCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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
func (client *StreamingEndpointsClient) getHandleResponse(resp *http.Response) (StreamingEndpointsGetResponse, error) {
	result := StreamingEndpointsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.StreamingEndpoint); err != nil {
		return StreamingEndpointsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *StreamingEndpointsClient) getHandleError(resp *http.Response) error {
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

// List - Lists the streaming endpoints in the account.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) List(resourceGroupName string, accountName string, options *StreamingEndpointsListOptions) *StreamingEndpointsListPager {
	return &StreamingEndpointsListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, resourceGroupName, accountName, options)
		},
		advancer: func(ctx context.Context, resp StreamingEndpointsListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.StreamingEndpointListResult.ODataNextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *StreamingEndpointsClient) listCreateRequest(ctx context.Context, resourceGroupName string, accountName string, options *StreamingEndpointsListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints"
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
	reqQP.Set("api-version", "2021-06-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *StreamingEndpointsClient) listHandleResponse(resp *http.Response) (StreamingEndpointsListResponse, error) {
	result := StreamingEndpointsListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.StreamingEndpointListResult); err != nil {
		return StreamingEndpointsListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *StreamingEndpointsClient) listHandleError(resp *http.Response) error {
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

// BeginScale - Scales an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginScale(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEntityScaleUnit, options *StreamingEndpointsBeginScaleOptions) (StreamingEndpointsScalePollerResponse, error) {
	resp, err := client.scale(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
	if err != nil {
		return StreamingEndpointsScalePollerResponse{}, err
	}
	result := StreamingEndpointsScalePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Scale", "", resp, client.pl, client.scaleHandleError)
	if err != nil {
		return StreamingEndpointsScalePollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsScalePoller{
		pt: pt,
	}
	return result, nil
}

// Scale - Scales an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) scale(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEntityScaleUnit, options *StreamingEndpointsBeginScaleOptions) (*http.Response, error) {
	req, err := client.scaleCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, client.scaleHandleError(resp)
	}
	return resp, nil
}

// scaleCreateRequest creates the Scale request.
func (client *StreamingEndpointsClient) scaleCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEntityScaleUnit, options *StreamingEndpointsBeginScaleOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}/scale"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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

// scaleHandleError handles the Scale error response.
func (client *StreamingEndpointsClient) scaleHandleError(resp *http.Response) error {
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

// BeginStart - Starts an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginStart(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStartOptions) (StreamingEndpointsStartPollerResponse, error) {
	resp, err := client.start(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return StreamingEndpointsStartPollerResponse{}, err
	}
	result := StreamingEndpointsStartPollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Start", "", resp, client.pl, client.startHandleError)
	if err != nil {
		return StreamingEndpointsStartPollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsStartPoller{
		pt: pt,
	}
	return result, nil
}

// Start - Starts an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) start(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStartOptions) (*http.Response, error) {
	req, err := client.startCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, client.startHandleError(resp)
	}
	return resp, nil
}

// startCreateRequest creates the Start request.
func (client *StreamingEndpointsClient) startCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStartOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}/start"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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

// startHandleError handles the Start error response.
func (client *StreamingEndpointsClient) startHandleError(resp *http.Response) error {
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

// BeginStop - Stops an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginStop(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStopOptions) (StreamingEndpointsStopPollerResponse, error) {
	resp, err := client.stop(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return StreamingEndpointsStopPollerResponse{}, err
	}
	result := StreamingEndpointsStopPollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Stop", "", resp, client.pl, client.stopHandleError)
	if err != nil {
		return StreamingEndpointsStopPollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsStopPoller{
		pt: pt,
	}
	return result, nil
}

// Stop - Stops an existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) stop(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStopOptions) (*http.Response, error) {
	req, err := client.stopCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusAccepted) {
		return nil, client.stopHandleError(resp)
	}
	return resp, nil
}

// stopCreateRequest creates the Stop request.
func (client *StreamingEndpointsClient) stopCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, options *StreamingEndpointsBeginStopOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}/stop"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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

// stopHandleError handles the Stop error response.
func (client *StreamingEndpointsClient) stopHandleError(resp *http.Response) error {
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

// BeginUpdate - Updates a existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) BeginUpdate(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginUpdateOptions) (StreamingEndpointsUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
	if err != nil {
		return StreamingEndpointsUpdatePollerResponse{}, err
	}
	result := StreamingEndpointsUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("StreamingEndpointsClient.Update", "", resp, client.pl, client.updateHandleError)
	if err != nil {
		return StreamingEndpointsUpdatePollerResponse{}, err
	}
	result.Poller = &StreamingEndpointsUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Updates a existing streaming endpoint.
// If the operation fails it returns the *ErrorResponse error type.
func (client *StreamingEndpointsClient) update(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, accountName, streamingEndpointName, parameters, options)
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
func (client *StreamingEndpointsClient) updateCreateRequest(ctx context.Context, resourceGroupName string, accountName string, streamingEndpointName string, parameters StreamingEndpoint, options *StreamingEndpointsBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Media/mediaservices/{accountName}/streamingEndpoints/{streamingEndpointName}"
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
	if streamingEndpointName == "" {
		return nil, errors.New("parameter streamingEndpointName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamingEndpointName}", url.PathEscape(streamingEndpointName))
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

// updateHandleError handles the Update error response.
func (client *StreamingEndpointsClient) updateHandleError(resp *http.Response) error {
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
