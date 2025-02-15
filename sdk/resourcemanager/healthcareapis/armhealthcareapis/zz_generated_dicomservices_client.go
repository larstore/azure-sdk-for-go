//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armhealthcareapis

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

// DicomServicesClient contains the methods for the DicomServices group.
// Don't use this type directly, use NewDicomServicesClient() instead.
type DicomServicesClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewDicomServicesClient creates a new instance of DicomServicesClient with the specified values.
func NewDicomServicesClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *DicomServicesClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &DicomServicesClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// BeginCreateOrUpdate - Creates or updates a DICOM Service resource with the specified parameters.
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) BeginCreateOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, dicomServiceName string, dicomservice DicomService, options *DicomServicesBeginCreateOrUpdateOptions) (DicomServicesCreateOrUpdatePollerResponse, error) {
	resp, err := client.createOrUpdate(ctx, resourceGroupName, workspaceName, dicomServiceName, dicomservice, options)
	if err != nil {
		return DicomServicesCreateOrUpdatePollerResponse{}, err
	}
	result := DicomServicesCreateOrUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("DicomServicesClient.CreateOrUpdate", "", resp, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return DicomServicesCreateOrUpdatePollerResponse{}, err
	}
	result.Poller = &DicomServicesCreateOrUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// CreateOrUpdate - Creates or updates a DICOM Service resource with the specified parameters.
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) createOrUpdate(ctx context.Context, resourceGroupName string, workspaceName string, dicomServiceName string, dicomservice DicomService, options *DicomServicesBeginCreateOrUpdateOptions) (*http.Response, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, resourceGroupName, workspaceName, dicomServiceName, dicomservice, options)
	if err != nil {
		return nil, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return nil, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated, http.StatusAccepted) {
		return nil, client.createOrUpdateHandleError(resp)
	}
	return resp, nil
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *DicomServicesClient) createOrUpdateCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, dicomServiceName string, dicomservice DicomService, options *DicomServicesBeginCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthcareApis/workspaces/{workspaceName}/dicomservices/{dicomServiceName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if dicomServiceName == "" {
		return nil, errors.New("parameter dicomServiceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dicomServiceName}", url.PathEscape(dicomServiceName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, dicomservice)
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *DicomServicesClient) createOrUpdateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// BeginDelete - Deletes a DICOM Service.
// If the operation fails it returns the *Error error type.
func (client *DicomServicesClient) BeginDelete(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, options *DicomServicesBeginDeleteOptions) (DicomServicesDeletePollerResponse, error) {
	resp, err := client.deleteOperation(ctx, resourceGroupName, dicomServiceName, workspaceName, options)
	if err != nil {
		return DicomServicesDeletePollerResponse{}, err
	}
	result := DicomServicesDeletePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("DicomServicesClient.Delete", "", resp, client.pl, client.deleteHandleError)
	if err != nil {
		return DicomServicesDeletePollerResponse{}, err
	}
	result.Poller = &DicomServicesDeletePoller{
		pt: pt,
	}
	return result, nil
}

// Delete - Deletes a DICOM Service.
// If the operation fails it returns the *Error error type.
func (client *DicomServicesClient) deleteOperation(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, options *DicomServicesBeginDeleteOptions) (*http.Response, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, dicomServiceName, workspaceName, options)
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
func (client *DicomServicesClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, options *DicomServicesBeginDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthcareApis/workspaces/{workspaceName}/dicomservices/{dicomServiceName}"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if dicomServiceName == "" {
		return nil, errors.New("parameter dicomServiceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dicomServiceName}", url.PathEscape(dicomServiceName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
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
func (client *DicomServicesClient) deleteHandleError(resp *http.Response) error {
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

// Get - Gets the properties of the specified DICOM Service.
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) Get(ctx context.Context, resourceGroupName string, workspaceName string, dicomServiceName string, options *DicomServicesGetOptions) (DicomServicesGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, workspaceName, dicomServiceName, options)
	if err != nil {
		return DicomServicesGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return DicomServicesGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return DicomServicesGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *DicomServicesClient) getCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, dicomServiceName string, options *DicomServicesGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthcareApis/workspaces/{workspaceName}/dicomservices/{dicomServiceName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	if dicomServiceName == "" {
		return nil, errors.New("parameter dicomServiceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dicomServiceName}", url.PathEscape(dicomServiceName))
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
func (client *DicomServicesClient) getHandleResponse(resp *http.Response) (DicomServicesGetResponse, error) {
	result := DicomServicesGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DicomService); err != nil {
		return DicomServicesGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *DicomServicesClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// ListByWorkspace - Lists all DICOM Services for the given workspace
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) ListByWorkspace(resourceGroupName string, workspaceName string, options *DicomServicesListByWorkspaceOptions) *DicomServicesListByWorkspacePager {
	return &DicomServicesListByWorkspacePager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByWorkspaceCreateRequest(ctx, resourceGroupName, workspaceName, options)
		},
		advancer: func(ctx context.Context, resp DicomServicesListByWorkspaceResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.DicomServiceCollection.NextLink)
		},
	}
}

// listByWorkspaceCreateRequest creates the ListByWorkspace request.
func (client *DicomServicesClient) listByWorkspaceCreateRequest(ctx context.Context, resourceGroupName string, workspaceName string, options *DicomServicesListByWorkspaceOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthcareApis/workspaces/{workspaceName}/dicomservices"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
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

// listByWorkspaceHandleResponse handles the ListByWorkspace response.
func (client *DicomServicesClient) listByWorkspaceHandleResponse(resp *http.Response) (DicomServicesListByWorkspaceResponse, error) {
	result := DicomServicesListByWorkspaceResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.DicomServiceCollection); err != nil {
		return DicomServicesListByWorkspaceResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByWorkspaceHandleError handles the ListByWorkspace error response.
func (client *DicomServicesClient) listByWorkspaceHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// BeginUpdate - Patch DICOM Service details.
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) BeginUpdate(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, dicomservicePatchResource DicomServicePatchResource, options *DicomServicesBeginUpdateOptions) (DicomServicesUpdatePollerResponse, error) {
	resp, err := client.update(ctx, resourceGroupName, dicomServiceName, workspaceName, dicomservicePatchResource, options)
	if err != nil {
		return DicomServicesUpdatePollerResponse{}, err
	}
	result := DicomServicesUpdatePollerResponse{
		RawResponse: resp,
	}
	pt, err := armruntime.NewPoller("DicomServicesClient.Update", "", resp, client.pl, client.updateHandleError)
	if err != nil {
		return DicomServicesUpdatePollerResponse{}, err
	}
	result.Poller = &DicomServicesUpdatePoller{
		pt: pt,
	}
	return result, nil
}

// Update - Patch DICOM Service details.
// If the operation fails it returns the *ErrorDetails error type.
func (client *DicomServicesClient) update(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, dicomservicePatchResource DicomServicePatchResource, options *DicomServicesBeginUpdateOptions) (*http.Response, error) {
	req, err := client.updateCreateRequest(ctx, resourceGroupName, dicomServiceName, workspaceName, dicomservicePatchResource, options)
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
func (client *DicomServicesClient) updateCreateRequest(ctx context.Context, resourceGroupName string, dicomServiceName string, workspaceName string, dicomservicePatchResource DicomServicePatchResource, options *DicomServicesBeginUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.HealthcareApis/workspaces/{workspaceName}/dicomservices/{dicomServiceName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if dicomServiceName == "" {
		return nil, errors.New("parameter dicomServiceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{dicomServiceName}", url.PathEscape(dicomServiceName))
	if workspaceName == "" {
		return nil, errors.New("parameter workspaceName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{workspaceName}", url.PathEscape(workspaceName))
	req, err := runtime.NewRequest(ctx, http.MethodPatch, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-06-01-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, dicomservicePatchResource)
}

// updateHandleError handles the Update error response.
func (client *DicomServicesClient) updateHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ErrorDetails{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
