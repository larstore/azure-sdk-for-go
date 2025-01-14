//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armautomation

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

// SourceControlSyncJobStreamsClient contains the methods for the SourceControlSyncJobStreams group.
// Don't use this type directly, use NewSourceControlSyncJobStreamsClient() instead.
type SourceControlSyncJobStreamsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewSourceControlSyncJobStreamsClient creates a new instance of SourceControlSyncJobStreamsClient with the specified values.
func NewSourceControlSyncJobStreamsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *SourceControlSyncJobStreamsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &SourceControlSyncJobStreamsClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Get - Retrieve a sync job stream identified by stream id.
// If the operation fails it returns the *ErrorResponse error type.
func (client *SourceControlSyncJobStreamsClient) Get(ctx context.Context, resourceGroupName string, automationAccountName string, sourceControlName string, sourceControlSyncJobID string, streamID string, options *SourceControlSyncJobStreamsGetOptions) (SourceControlSyncJobStreamsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, automationAccountName, sourceControlName, sourceControlSyncJobID, streamID, options)
	if err != nil {
		return SourceControlSyncJobStreamsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return SourceControlSyncJobStreamsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return SourceControlSyncJobStreamsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *SourceControlSyncJobStreamsClient) getCreateRequest(ctx context.Context, resourceGroupName string, automationAccountName string, sourceControlName string, sourceControlSyncJobID string, streamID string, options *SourceControlSyncJobStreamsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/sourceControls/{sourceControlName}/sourceControlSyncJobs/{sourceControlSyncJobId}/streams/{streamId}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if automationAccountName == "" {
		return nil, errors.New("parameter automationAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{automationAccountName}", url.PathEscape(automationAccountName))
	if sourceControlName == "" {
		return nil, errors.New("parameter sourceControlName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{sourceControlName}", url.PathEscape(sourceControlName))
	urlPath = strings.ReplaceAll(urlPath, "{sourceControlSyncJobId}", url.PathEscape(sourceControlSyncJobID))
	if streamID == "" {
		return nil, errors.New("parameter streamID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{streamId}", url.PathEscape(streamID))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-01-13-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *SourceControlSyncJobStreamsClient) getHandleResponse(resp *http.Response) (SourceControlSyncJobStreamsGetResponse, error) {
	result := SourceControlSyncJobStreamsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.SourceControlSyncJobStreamByID); err != nil {
		return SourceControlSyncJobStreamsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *SourceControlSyncJobStreamsClient) getHandleError(resp *http.Response) error {
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

// ListBySyncJob - Retrieve a list of sync job streams identified by sync job id.
// If the operation fails it returns the *ErrorResponse error type.
func (client *SourceControlSyncJobStreamsClient) ListBySyncJob(resourceGroupName string, automationAccountName string, sourceControlName string, sourceControlSyncJobID string, options *SourceControlSyncJobStreamsListBySyncJobOptions) *SourceControlSyncJobStreamsListBySyncJobPager {
	return &SourceControlSyncJobStreamsListBySyncJobPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listBySyncJobCreateRequest(ctx, resourceGroupName, automationAccountName, sourceControlName, sourceControlSyncJobID, options)
		},
		advancer: func(ctx context.Context, resp SourceControlSyncJobStreamsListBySyncJobResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.SourceControlSyncJobStreamsListBySyncJob.NextLink)
		},
	}
}

// listBySyncJobCreateRequest creates the ListBySyncJob request.
func (client *SourceControlSyncJobStreamsClient) listBySyncJobCreateRequest(ctx context.Context, resourceGroupName string, automationAccountName string, sourceControlName string, sourceControlSyncJobID string, options *SourceControlSyncJobStreamsListBySyncJobOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Automation/automationAccounts/{automationAccountName}/sourceControls/{sourceControlName}/sourceControlSyncJobs/{sourceControlSyncJobId}/streams"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if automationAccountName == "" {
		return nil, errors.New("parameter automationAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{automationAccountName}", url.PathEscape(automationAccountName))
	if sourceControlName == "" {
		return nil, errors.New("parameter sourceControlName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{sourceControlName}", url.PathEscape(sourceControlName))
	urlPath = strings.ReplaceAll(urlPath, "{sourceControlSyncJobId}", url.PathEscape(sourceControlSyncJobID))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	reqQP.Set("api-version", "2020-01-13-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listBySyncJobHandleResponse handles the ListBySyncJob response.
func (client *SourceControlSyncJobStreamsClient) listBySyncJobHandleResponse(resp *http.Response) (SourceControlSyncJobStreamsListBySyncJobResponse, error) {
	result := SourceControlSyncJobStreamsListBySyncJobResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.SourceControlSyncJobStreamsListBySyncJob); err != nil {
		return SourceControlSyncJobStreamsListBySyncJobResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listBySyncJobHandleError handles the ListBySyncJob error response.
func (client *SourceControlSyncJobStreamsClient) listBySyncJobHandleError(resp *http.Response) error {
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
