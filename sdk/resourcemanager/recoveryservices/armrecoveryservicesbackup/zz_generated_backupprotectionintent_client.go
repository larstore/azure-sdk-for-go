//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armrecoveryservicesbackup

import (
	"context"
	"errors"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/arm"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"net/url"
	"strings"
)

// BackupProtectionIntentClient contains the methods for the BackupProtectionIntent group.
// Don't use this type directly, use NewBackupProtectionIntentClient() instead.
type BackupProtectionIntentClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewBackupProtectionIntentClient creates a new instance of BackupProtectionIntentClient with the specified values.
func NewBackupProtectionIntentClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *BackupProtectionIntentClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &BackupProtectionIntentClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// List - Provides a pageable list of all intents that are present within a vault.
// If the operation fails it returns a generic error.
func (client *BackupProtectionIntentClient) List(vaultName string, resourceGroupName string, options *BackupProtectionIntentListOptions) *BackupProtectionIntentListPager {
	return &BackupProtectionIntentListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, vaultName, resourceGroupName, options)
		},
		advancer: func(ctx context.Context, resp BackupProtectionIntentListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.ProtectionIntentResourceList.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *BackupProtectionIntentClient) listCreateRequest(ctx context.Context, vaultName string, resourceGroupName string, options *BackupProtectionIntentListOptions) (*policy.Request, error) {
	urlPath := "/Subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupProtectionIntents"
	if vaultName == "" {
		return nil, errors.New("parameter vaultName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{vaultName}", url.PathEscape(vaultName))
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
	reqQP.Set("api-version", "2021-08-01")
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.SkipToken != nil {
		reqQP.Set("$skipToken", *options.SkipToken)
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *BackupProtectionIntentClient) listHandleResponse(resp *http.Response) (BackupProtectionIntentListResponse, error) {
	result := BackupProtectionIntentListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ProtectionIntentResourceList); err != nil {
		return BackupProtectionIntentListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *BackupProtectionIntentClient) listHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	if len(body) == 0 {
		return runtime.NewResponseError(errors.New(resp.Status), resp)
	}
	return runtime.NewResponseError(errors.New(string(body)), resp)
}
