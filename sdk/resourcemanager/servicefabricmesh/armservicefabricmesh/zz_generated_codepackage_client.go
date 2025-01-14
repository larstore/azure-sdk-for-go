//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armservicefabricmesh

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

// CodePackageClient contains the methods for the CodePackage group.
// Don't use this type directly, use NewCodePackageClient() instead.
type CodePackageClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewCodePackageClient creates a new instance of CodePackageClient with the specified values.
func NewCodePackageClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *CodePackageClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &CodePackageClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// GetContainerLogs - Gets the logs for the container of the specified code package of the service replica.
// If the operation fails it returns the *ErrorModel error type.
func (client *CodePackageClient) GetContainerLogs(ctx context.Context, resourceGroupName string, applicationResourceName string, serviceResourceName string, replicaName string, codePackageName string, options *CodePackageGetContainerLogsOptions) (CodePackageGetContainerLogsResponse, error) {
	req, err := client.getContainerLogsCreateRequest(ctx, resourceGroupName, applicationResourceName, serviceResourceName, replicaName, codePackageName, options)
	if err != nil {
		return CodePackageGetContainerLogsResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return CodePackageGetContainerLogsResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return CodePackageGetContainerLogsResponse{}, client.getContainerLogsHandleError(resp)
	}
	return client.getContainerLogsHandleResponse(resp)
}

// getContainerLogsCreateRequest creates the GetContainerLogs request.
func (client *CodePackageClient) getContainerLogsCreateRequest(ctx context.Context, resourceGroupName string, applicationResourceName string, serviceResourceName string, replicaName string, codePackageName string, options *CodePackageGetContainerLogsOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabricMesh/applications/{applicationResourceName}/services/{serviceResourceName}/replicas/{replicaName}/codePackages/{codePackageName}/logs"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	urlPath = strings.ReplaceAll(urlPath, "{applicationResourceName}", applicationResourceName)
	urlPath = strings.ReplaceAll(urlPath, "{serviceResourceName}", serviceResourceName)
	urlPath = strings.ReplaceAll(urlPath, "{replicaName}", replicaName)
	if codePackageName == "" {
		return nil, errors.New("parameter codePackageName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{codePackageName}", url.PathEscape(codePackageName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2018-09-01-preview")
	if options != nil && options.Tail != nil {
		reqQP.Set("tail", strconv.FormatInt(int64(*options.Tail), 10))
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getContainerLogsHandleResponse handles the GetContainerLogs response.
func (client *CodePackageClient) getContainerLogsHandleResponse(resp *http.Response) (CodePackageGetContainerLogsResponse, error) {
	result := CodePackageGetContainerLogsResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ContainerLogs); err != nil {
		return CodePackageGetContainerLogsResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getContainerLogsHandleError handles the GetContainerLogs error response.
func (client *CodePackageClient) getContainerLogsHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorModel{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
