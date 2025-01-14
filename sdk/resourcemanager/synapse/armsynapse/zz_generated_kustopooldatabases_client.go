//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsynapse

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

// KustoPoolDatabasesClient contains the methods for the KustoPoolDatabases group.
// Don't use this type directly, use NewKustoPoolDatabasesClient() instead.
type KustoPoolDatabasesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewKustoPoolDatabasesClient creates a new instance of KustoPoolDatabasesClient with the specified values.
func NewKustoPoolDatabasesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *KustoPoolDatabasesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &KustoPoolDatabasesClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreateOrUpdate - Creates or updates a database.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginCreateOrUpdateOptions) (KustoPoolDatabasesCreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, parameters, options)
	if err != nil {
		return KustoPoolDatabasesCreateOrUpdatePollerResponse{}, err
	}
	result := KustoPoolDatabasesCreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("KustoPoolDatabasesClient.CreateOrUpdate", "", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return KustoPoolDatabasesCreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &KustoPoolDatabasesCreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - Creates or updates a database.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) createOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, parameters, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *KustoPoolDatabasesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/kustoPools/{kustoPoolName}/databases/{databaseName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if kustoPoolName == "" {
		return nil, errors.New("parameter kustoPoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{kustoPoolName}", url.PathEscape(kustoPoolName))
	if databaseName == "" {
		return nil, errors.New("parameter databaseName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{databaseName}", url.PathEscape(databaseName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *KustoPoolDatabasesClient) createOrUpdateHandleError(resp *http.Response) error {
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

// BeginDelete - Deletes the database with the given name.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) BeginDelete(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, options *KustoPoolDatabasesBeginDeleteOptions) (KustoPoolDatabasesDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, options)
	if err != nil {
		return KustoPoolDatabasesDeletePollerResponse{}, err
	}
	result := KustoPoolDatabasesDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("KustoPoolDatabasesClient.Delete", "", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return KustoPoolDatabasesDeletePollerResponse{}, err
	}
	result.Poller = &KustoPoolDatabasesDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes the database with the given name.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) deleteOperation(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, options *KustoPoolDatabasesBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, options)
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
func (client *KustoPoolDatabasesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, options *KustoPoolDatabasesBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/kustoPools/{kustoPoolName}/databases/{databaseName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if kustoPoolName == "" {
		return nil, errors.New("parameter kustoPoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{kustoPoolName}", url.PathEscape(kustoPoolName))
	if databaseName == "" {
		return nil, errors.New("parameter databaseName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{databaseName}", url.PathEscape(databaseName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *KustoPoolDatabasesClient) deleteHandleError(resp *http.Response) error {
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

// Get - Returns a database.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) Get(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, options *KustoPoolDatabasesGetOptions) (KustoPoolDatabasesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, options)
	if err != nil {
		return KustoPoolDatabasesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return KustoPoolDatabasesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return KustoPoolDatabasesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *KustoPoolDatabasesClient) getCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, options *KustoPoolDatabasesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/kustoPools/{kustoPoolName}/databases/{databaseName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if kustoPoolName == "" {
		return nil, errors.New("parameter kustoPoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{kustoPoolName}", url.PathEscape(kustoPoolName))
	if databaseName == "" {
		return nil, errors.New("parameter databaseName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{databaseName}", url.PathEscape(databaseName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *KustoPoolDatabasesClient) getHandleResponse(resp *http.Response) (KustoPoolDatabasesGetResponse, error) {
	result := KustoPoolDatabasesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result); err != nil {
		return KustoPoolDatabasesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *KustoPoolDatabasesClient) getHandleError(resp *http.Response) error {
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

// ListByKustoPool - Returns the list of databases of the given Kusto pool.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) ListByKustoPool(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, options *KustoPoolDatabasesListByKustoPoolOptions) (KustoPoolDatabasesListByKustoPoolResponse, error) {
	req, err := client.listByKustoPoolCreateRequest(ctx, resourceGroupName, workspaceName, kustoPoolName, options)
	if err != nil {
		return KustoPoolDatabasesListByKustoPoolResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return KustoPoolDatabasesListByKustoPoolResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return KustoPoolDatabasesListByKustoPoolResponse{}, client.listByKustoPoolHandleError(resp)
	}
	return client.listByKustoPoolHandleResponse(resp)
}

// listByKustoPoolCreateRequest creates the ListByKustoPool request.
func (client *KustoPoolDatabasesClient) listByKustoPoolCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, options *KustoPoolDatabasesListByKustoPoolOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/kustoPools/{kustoPoolName}/databases"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if kustoPoolName == "" {
		return nil, errors.New("parameter kustoPoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{kustoPoolName}", url.PathEscape(kustoPoolName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByKustoPoolHandleResponse handles the ListByKustoPool response.
func (client *KustoPoolDatabasesClient) listByKustoPoolHandleResponse(resp *http.Response) (KustoPoolDatabasesListByKustoPoolResponse, error) {
	result := KustoPoolDatabasesListByKustoPoolResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DatabaseListResult); err != nil {
		return KustoPoolDatabasesListByKustoPoolResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByKustoPoolHandleError handles the ListByKustoPool error response.
func (client *KustoPoolDatabasesClient) listByKustoPoolHandleError(resp *http.Response) error {
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

// BeginUpdate - Updates a database.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) BeginUpdate(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginUpdateOptions) (KustoPoolDatabasesUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, parameters, options)
	if err != nil {
		return KustoPoolDatabasesUpdatePollerResponse{}, err
	}
	result := KustoPoolDatabasesUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("KustoPoolDatabasesClient.Update", "", resp, client.pl, client.updateHandleError)
	if err != nil {
		return KustoPoolDatabasesUpdatePollerResponse{}, err
	}
	result.Poller = &KustoPoolDatabasesUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Updates a database.
// If the operation fails it returns the *ErrorResponse error type.
func (client *KustoPoolDatabasesClient) update(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, workspaceName, kustoPoolName, databaseName, parameters, options)
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
func (client *KustoPoolDatabasesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, kustoPoolName string, databaseName string, parameters DatabaseClassification, options *KustoPoolDatabasesBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Synapse/workspaces/{workspaceName}/kustoPools/{kustoPoolName}/databases/{databaseName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if kustoPoolName == "" {
		return nil, errors.New("parameter kustoPoolName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{kustoPoolName}", url.PathEscape(kustoPoolName))
	if databaseName == "" {
		return nil, errors.New("parameter databaseName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{databaseName}", url.PathEscape(databaseName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// updateHandleError handles the Update error response.
func (client *KustoPoolDatabasesClient) updateHandleError(resp *http.Response) error {
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
