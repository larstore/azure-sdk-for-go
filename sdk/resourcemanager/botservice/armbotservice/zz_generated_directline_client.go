//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armbotservice

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

// DirectLineClient contains the methods for the DirectLine group.
// Don't use this type directly, use NewDirectLineClient() instead.
type DirectLineClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewDirectLineClient creates a new instance of DirectLineClient with the specified values.
func NewDirectLineClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *DirectLineClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &DirectLineClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// RegenerateKeys - Regenerates secret keys and returns them for the DirectLine Channel of a particular BotService resource
// If the operation fails it returns the *Error error type.
func (client *DirectLineClient) RegenerateKeys(ctx context.Context, resourceGroupName string, resourceName string, channelName RegenerateKeysChannelName, parameters SiteInfo, options *DirectLineRegenerateKeysOptions) (DirectLineRegenerateKeysResponse, error) {
	req, err := client.regenerateKeysCreateRequest(ctx, resourceGroupName, resourceName, channelName, parameters, options)
	if err != nil {
		return DirectLineRegenerateKeysResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DirectLineRegenerateKeysResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DirectLineRegenerateKeysResponse{}, client.regenerateKeysHandleError(resp)
	}
	return client.regenerateKeysHandleResponse(resp)
}

// regenerateKeysCreateRequest creates the RegenerateKeys request.
func (client *DirectLineClient) regenerateKeysCreateRequest(ctx context.Context, resourceGroupName string, resourceName string, channelName RegenerateKeysChannelName, parameters SiteInfo, options *DirectLineRegenerateKeysOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.BotService/botServices/{resourceName}/channels/{channelName}/regeneratekeys"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if resourceName == "" {
		return nil, errors.New("parameter resourceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceName}", url.PathEscape(resourceName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if channelName == "" {
		return nil, errors.New("parameter channelName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{channelName}", url.PathEscape(string(channelName)))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-05-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// regenerateKeysHandleResponse handles the RegenerateKeys response.
func (client *DirectLineClient) regenerateKeysHandleResponse(resp *http.Response) (DirectLineRegenerateKeysResponse, error) {
	result := DirectLineRegenerateKeysResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.BotChannel); err != nil {
		return DirectLineRegenerateKeysResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// regenerateKeysHandleError handles the RegenerateKeys error response.
func (client *DirectLineClient) regenerateKeysHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := Error{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
