//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armvmwarecloudsimple

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

// DedicatedCloudNodesClient contains the methods for the DedicatedCloudNodes group.
// Don't use this type directly, use NewDedicatedCloudNodesClient() instead.
type DedicatedCloudNodesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
	referer        string
}

// NewDedicatedCloudNodesClient creates a new instance of DedicatedCloudNodesClient with the specified values.
func NewDedicatedCloudNodesClient(subscriptionID string, referer string, credential azcore.TokenCredential, options *arm.ClientOptions) *DedicatedCloudNodesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &DedicatedCloudNodesClient{subscriptionID: subscriptionID, referer: referer, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreateOrUpdate - Returns dedicated cloud node by its name
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, dedicatedCloudNodeRequest DedicatedCloudNode, options *DedicatedCloudNodesBeginCreateOrUpdateOptions) (DedicatedCloudNodesCreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, resourceGroupName, dedicatedCloudNodeName, dedicatedCloudNodeRequest, options)
	if err != nil {
		return DedicatedCloudNodesCreateOrUpdatePollerResponse{}, err
	}
	result := DedicatedCloudNodesCreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("DedicatedCloudNodesClient.CreateOrUpdate", "", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return DedicatedCloudNodesCreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &DedicatedCloudNodesCreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - Returns dedicated cloud node by its name
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) createOrUpdate(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, dedicatedCloudNodeRequest DedicatedCloudNode, options *DedicatedCloudNodesBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, dedicatedCloudNodeName, dedicatedCloudNodeRequest, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *DedicatedCloudNodesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, dedicatedCloudNodeRequest DedicatedCloudNode, options *DedicatedCloudNodesBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes/{dedicatedCloudNodeName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if dedicatedCloudNodeName == "" {
		return nil, errors.New("parameter dedicatedCloudNodeName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dedicatedCloudNodeName}", url.PathEscape(dedicatedCloudNodeName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-04-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Referer", client.referer)
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, dedicatedCloudNodeRequest)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *DedicatedCloudNodesClient) createOrUpdateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Delete - Delete dedicated cloud node
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) Delete(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, options *DedicatedCloudNodesDeleteOptions) (DedicatedCloudNodesDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, dedicatedCloudNodeName, options)
	if err != nil {
		return DedicatedCloudNodesDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DedicatedCloudNodesDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusNoContent) {
		return DedicatedCloudNodesDeleteResponse{}, client.deleteHandleError(resp)
	}
	return DedicatedCloudNodesDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *DedicatedCloudNodesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, options *DedicatedCloudNodesDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes/{dedicatedCloudNodeName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if dedicatedCloudNodeName == "" {
		return nil, errors.New("parameter dedicatedCloudNodeName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dedicatedCloudNodeName}", url.PathEscape(dedicatedCloudNodeName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-04-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *DedicatedCloudNodesClient) deleteHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Get - Returns dedicated cloud node
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) Get(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, options *DedicatedCloudNodesGetOptions) (DedicatedCloudNodesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, dedicatedCloudNodeName, options)
	if err != nil {
		return DedicatedCloudNodesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DedicatedCloudNodesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DedicatedCloudNodesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *DedicatedCloudNodesClient) getCreateRequest(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, options *DedicatedCloudNodesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes/{dedicatedCloudNodeName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if dedicatedCloudNodeName == "" {
		return nil, errors.New("parameter dedicatedCloudNodeName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dedicatedCloudNodeName}", url.PathEscape(dedicatedCloudNodeName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-04-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *DedicatedCloudNodesClient) getHandleResponse(resp *http.Response) (DedicatedCloudNodesGetResponse, error) {
	result := DedicatedCloudNodesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DedicatedCloudNode); err != nil {
		return DedicatedCloudNodesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *DedicatedCloudNodesClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListByResourceGroup - Returns list of dedicate cloud nodes within resource group
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) ListByResourceGroup(resourceGroupName string, options *DedicatedCloudNodesListByResourceGroupOptions) *DedicatedCloudNodesListByResourceGroupPager {
	return &DedicatedCloudNodesListByResourceGroupPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByResourceGroupCreateRequest(ctx, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp DedicatedCloudNodesListByResourceGroupResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.DedicatedCloudNodeListResponse.NextLink)
		},
	}
}

// listByResourceGroupCreateRequest creates the ListByResourceGroup request.
func (client *DedicatedCloudNodesClient) listByResourceGroupCreateRequest(ctx context.Context, resourceGroupName string, options *DedicatedCloudNodesListByResourceGroupOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes"
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
	reqQP.Set("api-version", "2019-04-01")
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.Top != nil {
		reqQP.Set("$top", strconv.FormatInt(int64(*options.Top), 10))
	}
	if options != nil && options.SkipToken != nil {
		reqQP.Set("$skipToken", *options.SkipToken)
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByResourceGroupHandleResponse handles the ListByResourceGroup response.
func (client *DedicatedCloudNodesClient) listByResourceGroupHandleResponse(resp *http.Response) (DedicatedCloudNodesListByResourceGroupResponse, error) {
	result := DedicatedCloudNodesListByResourceGroupResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DedicatedCloudNodeListResponse); err != nil {
		return DedicatedCloudNodesListByResourceGroupResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByResourceGroupHandleError handles the ListByResourceGroup error response.
func (client *DedicatedCloudNodesClient) listByResourceGroupHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListBySubscription - Returns list of dedicate cloud nodes within subscription
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) ListBySubscription(options *DedicatedCloudNodesListBySubscriptionOptions) *DedicatedCloudNodesListBySubscriptionPager {
	return &DedicatedCloudNodesListBySubscriptionPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listBySubscriptionCreateRequest(ctx, options)
		},
		advancer: func(ctx context.Context, resp DedicatedCloudNodesListBySubscriptionResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.DedicatedCloudNodeListResponse.NextLink)
		},
	}
}

// listBySubscriptionCreateRequest creates the ListBySubscription request.
func (client *DedicatedCloudNodesClient) listBySubscriptionCreateRequest(ctx context.Context, options *DedicatedCloudNodesListBySubscriptionOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-04-01")
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.Top != nil {
		reqQP.Set("$top", strconv.FormatInt(int64(*options.Top), 10))
	}
	if options != nil && options.SkipToken != nil {
		reqQP.Set("$skipToken", *options.SkipToken)
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listBySubscriptionHandleResponse handles the ListBySubscription response.
func (client *DedicatedCloudNodesClient) listBySubscriptionHandleResponse(resp *http.Response) (DedicatedCloudNodesListBySubscriptionResponse, error) {
	result := DedicatedCloudNodesListBySubscriptionResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DedicatedCloudNodeListResponse); err != nil {
		return DedicatedCloudNodesListBySubscriptionResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listBySubscriptionHandleError handles the ListBySubscription error response.
func (client *DedicatedCloudNodesClient) listBySubscriptionHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// Update - Patches dedicated node properties
// If the operation fails it returns the *CSRPError error type.
func (client *DedicatedCloudNodesClient) Update(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, dedicatedCloudNodeRequest PatchPayload, options *DedicatedCloudNodesUpdateOptions) (DedicatedCloudNodesUpdateResponse, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, dedicatedCloudNodeName, dedicatedCloudNodeRequest, options)
	if err != nil {
		return DedicatedCloudNodesUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DedicatedCloudNodesUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DedicatedCloudNodesUpdateResponse{}, client.updateHandleError(resp)
	}
	return client.updateHandleResponse(resp)
}

// updateCreateRequest creates the Update request.
func (client *DedicatedCloudNodesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, dedicatedCloudNodeName string, dedicatedCloudNodeRequest PatchPayload, options *DedicatedCloudNodesUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.VMwareCloudSimple/dedicatedCloudNodes/{dedicatedCloudNodeName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if dedicatedCloudNodeName == "" {
		return nil, errors.New("parameter dedicatedCloudNodeName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dedicatedCloudNodeName}", url.PathEscape(dedicatedCloudNodeName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2019-04-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, dedicatedCloudNodeRequest)
}

// updateHandleResponse handles the Update response.
func (client *DedicatedCloudNodesClient) updateHandleResponse(resp *http.Response) (DedicatedCloudNodesUpdateResponse, error) {
	result := DedicatedCloudNodesUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DedicatedCloudNode); err != nil {
		return DedicatedCloudNodesUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// updateHandleError handles the Update error response.
func (client *DedicatedCloudNodesClient) updateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := CSRPError{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
