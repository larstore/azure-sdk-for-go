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

// ProtectionIntentClient contains the methods for the ProtectionIntent group.
// Don't use this type directly, use NewProtectionIntentClient() instead.
type ProtectionIntentClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewProtectionIntentClient creates a new instance of ProtectionIntentClient with the specified values.
func NewProtectionIntentClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *ProtectionIntentClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &ProtectionIntentClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// CreateOrUpdate - Create Intent for Enabling backup of an item. This is a synchronous operation.
// If the operation fails it returns a generic error.
func (client *ProtectionIntentClient) CreateOrUpdate(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, parameters ProtectionIntentResource, options *ProtectionIntentCreateOrUpdateOptions) (ProtectionIntentCreateOrUpdateResponse, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, vaultName, resourceGroupName, fabricName, intentObjectName, parameters, options)
	if err != nil {
		return ProtectionIntentCreateOrUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ProtectionIntentCreateOrUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return ProtectionIntentCreateOrUpdateResponse{}, client.createOrUpdateHandleError(resp)
	}
	return client.createOrUpdateHandleResponse(resp)
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *ProtectionIntentClient) createOrUpdateCreateRequest(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, parameters ProtectionIntentResource, options *ProtectionIntentCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/Subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupFabrics/{fabricName}/backupProtectionIntent/{intentObjectName}"
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
	if fabricName == "" {
		return nil, errors.New("parameter fabricName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{fabricName}", url.PathEscape(fabricName))
	if intentObjectName == "" {
		return nil, errors.New("parameter intentObjectName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{intentObjectName}", url.PathEscape(intentObjectName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createOrUpdateHandleResponse handles the CreateOrUpdate response.
func (client *ProtectionIntentClient) createOrUpdateHandleResponse(resp *http.Response) (ProtectionIntentCreateOrUpdateResponse, error) {
	result := ProtectionIntentCreateOrUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ProtectionIntentResource); err != nil {
		return ProtectionIntentCreateOrUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *ProtectionIntentClient) createOrUpdateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	if len(body) == 0 {
		return runtime.NewResponseError(errors.New(resp.Status), resp)
	}
	return runtime.NewResponseError(errors.New(string(body)), resp)
}

// Delete - Used to remove intent from an item
// If the operation fails it returns a generic error.
func (client *ProtectionIntentClient) Delete(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, options *ProtectionIntentDeleteOptions) (ProtectionIntentDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, vaultName, resourceGroupName, fabricName, intentObjectName, options)
	if err != nil {
		return ProtectionIntentDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ProtectionIntentDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusNoContent) {
		return ProtectionIntentDeleteResponse{}, client.deleteHandleError(resp)
	}
	return ProtectionIntentDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *ProtectionIntentClient) deleteCreateRequest(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, options *ProtectionIntentDeleteOptions) (*policy.Request, error) {
	urlPath := "/Subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupFabrics/{fabricName}/backupProtectionIntent/{intentObjectName}"
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
	if fabricName == "" {
		return nil, errors.New("parameter fabricName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{fabricName}", url.PathEscape(fabricName))
	if intentObjectName == "" {
		return nil, errors.New("parameter intentObjectName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{intentObjectName}", url.PathEscape(intentObjectName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *ProtectionIntentClient) deleteHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	if len(body) == 0 {
		return runtime.NewResponseError(errors.New(resp.Status), resp)
	}
	return runtime.NewResponseError(errors.New(string(body)), resp)
}

// Get - Provides the details of the protection intent up item. This is an asynchronous operation. To know the status of the operation, call the GetItemOperationResult
// API.
// If the operation fails it returns a generic error.
func (client *ProtectionIntentClient) Get(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, options *ProtectionIntentGetOptions) (ProtectionIntentGetResponse, error) {
	req, err := client.getCreateRequest(ctx, vaultName, resourceGroupName, fabricName, intentObjectName, options)
	if err != nil {
		return ProtectionIntentGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ProtectionIntentGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return ProtectionIntentGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *ProtectionIntentClient) getCreateRequest(ctx context.Context, vaultName string, resourceGroupName string, fabricName string, intentObjectName string, options *ProtectionIntentGetOptions) (*policy.Request, error) {
	urlPath := "/Subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupFabrics/{fabricName}/backupProtectionIntent/{intentObjectName}"
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
	if fabricName == "" {
		return nil, errors.New("parameter fabricName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{fabricName}", url.PathEscape(fabricName))
	if intentObjectName == "" {
		return nil, errors.New("parameter intentObjectName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{intentObjectName}", url.PathEscape(intentObjectName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *ProtectionIntentClient) getHandleResponse(resp *http.Response) (ProtectionIntentGetResponse, error) {
	result := ProtectionIntentGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ProtectionIntentResource); err != nil {
		return ProtectionIntentGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *ProtectionIntentClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	if len(body) == 0 {
		return runtime.NewResponseError(errors.New(resp.Status), resp)
	}
	return runtime.NewResponseError(errors.New(string(body)), resp)
}

// Validate - It will validate followings
// 1. Vault capacity
// 2. VM is already protected
// 3. Any VM related configuration passed in properties.
// If the operation fails it returns a generic error.
func (client *ProtectionIntentClient) Validate(ctx context.Context, azureRegion string, parameters PreValidateEnableBackupRequest, options *ProtectionIntentValidateOptions) (ProtectionIntentValidateResponse, error) {
	req, err := client.validateCreateRequest(ctx, azureRegion, parameters, options)
	if err != nil {
		return ProtectionIntentValidateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return ProtectionIntentValidateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return ProtectionIntentValidateResponse{}, client.validateHandleError(resp)
	}
	return client.validateHandleResponse(resp)
}

// validateCreateRequest creates the Validate request.
func (client *ProtectionIntentClient) validateCreateRequest(ctx context.Context, azureRegion string, parameters PreValidateEnableBackupRequest, options *ProtectionIntentValidateOptions) (*policy.Request, error) {
	urlPath := "/Subscriptions/{subscriptionId}/providers/Microsoft.RecoveryServices/locations/{azureRegion}/backupPreValidateProtection"
	if azureRegion == "" {
		return nil, errors.New("parameter azureRegion cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{azureRegion}", url.PathEscape(azureRegion))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodPost, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-08-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// validateHandleResponse handles the Validate response.
func (client *ProtectionIntentClient) validateHandleResponse(resp *http.Response) (ProtectionIntentValidateResponse, error) {
	result := ProtectionIntentValidateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.PreValidateEnableBackupResponse); err != nil {
		return ProtectionIntentValidateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// validateHandleError handles the Validate error response.
func (client *ProtectionIntentClient) validateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	if len(body) == 0 {
		return runtime.NewResponseError(errors.New(resp.Status), resp)
	}
	return runtime.NewResponseError(errors.New(string(body)), resp)
}
