//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armavs

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

// ScriptPackagesClient contains the methods for the ScriptPackages group.
// Don't use this type directly, use NewScriptPackagesClient() instead.
type ScriptPackagesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewScriptPackagesClient creates a new instance of ScriptPackagesClient with the specified values.
func NewScriptPackagesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *ScriptPackagesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &ScriptPackagesClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Get - Get a script package available to run on a private cloud
// If the operation fails it returns the *CloudError error type.
func (client *ScriptPackagesClient) Get(ctx context.Context, resourceGroupName string, privateCloudName string, scriptPackageName string, options *ScriptPackagesGetOptions) (ScriptPackagesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, privateCloudName, scriptPackageName, options)
	if err != nil {
		return ScriptPackagesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ScriptPackagesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return ScriptPackagesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *ScriptPackagesClient) getCreateRequest(ctx context.Context, resourceGroupName string, privateCloudName string, scriptPackageName string, options *ScriptPackagesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AVS/privateClouds/{privateCloudName}/scriptPackages/{scriptPackageName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if privateCloudName == "" {
		return nil, errors.New("parameter privateCloudName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{privateCloudName}", url.PathEscape(privateCloudName))
	if scriptPackageName == "" {
		return nil, errors.New("parameter scriptPackageName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{scriptPackageName}", url.PathEscape(scriptPackageName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-12-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *ScriptPackagesClient) getHandleResponse(resp *http.Response) (ScriptPackagesGetResponse, error) {
	result := ScriptPackagesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ScriptPackage); err != nil {
		return ScriptPackagesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *ScriptPackagesClient) getHandleError(resp *http.Response) error {
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

// List - List script packages available to run on the private cloud
// If the operation fails it returns the *CloudError error type.
func (client *ScriptPackagesClient) List(resourceGroupName string, privateCloudName string, options *ScriptPackagesListOptions) *ScriptPackagesListPager {
	return &ScriptPackagesListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, resourceGroupName, privateCloudName, options)
		},
		advancer: func(ctx context.Context, resp ScriptPackagesListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ScriptPackagesList.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *ScriptPackagesClient) listCreateRequest(ctx context.Context, resourceGroupName string, privateCloudName string, options *ScriptPackagesListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.AVS/privateClouds/{privateCloudName}/scriptPackages"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if privateCloudName == "" {
		return nil, errors.New("parameter privateCloudName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{privateCloudName}", url.PathEscape(privateCloudName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-12-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *ScriptPackagesClient) listHandleResponse(resp *http.Response) (ScriptPackagesListResponse, error) {
	result := ScriptPackagesListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ScriptPackagesList); err != nil {
		return ScriptPackagesListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *ScriptPackagesClient) listHandleError(resp *http.Response) error {
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
