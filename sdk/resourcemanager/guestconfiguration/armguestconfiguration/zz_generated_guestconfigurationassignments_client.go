//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armguestconfiguration

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

// GuestConfigurationAssignmentsClient contains the methods for the GuestConfigurationAssignments group.
// Don't use this type directly, use NewGuestConfigurationAssignmentsClient() instead.
type GuestConfigurationAssignmentsClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewGuestConfigurationAssignmentsClient creates a new instance of GuestConfigurationAssignmentsClient with the specified values.
func NewGuestConfigurationAssignmentsClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *GuestConfigurationAssignmentsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &GuestConfigurationAssignmentsClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// CreateOrUpdate - Creates an association between a VM and guest configuration
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) CreateOrUpdate(ctx context.Context, guestConfigurationAssignmentName string, resourceGroupName string, vmName string, parameters GuestConfigurationAssignment, options *GuestConfigurationAssignmentsCreateOrUpdateOptions) (GuestConfigurationAssignmentsCreateOrUpdateResponse, error) {
	req, err := client.createOrUpdateCreateRequest(ctx, guestConfigurationAssignmentName, resourceGroupName, vmName, parameters, options)
	if err != nil {
		return GuestConfigurationAssignmentsCreateOrUpdateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsCreateOrUpdateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusCreated) {
		return GuestConfigurationAssignmentsCreateOrUpdateResponse{}, client.createOrUpdateHandleError(resp)
	}
	return client.createOrUpdateHandleResponse(resp)
}

// createOrUpdateCreateRequest creates the CreateOrUpdate request.
func (client *GuestConfigurationAssignmentsClient) createOrUpdateCreateRequest(ctx context.Context, guestConfigurationAssignmentName string, resourceGroupName string, vmName string, parameters GuestConfigurationAssignment, options *GuestConfigurationAssignmentsCreateOrUpdateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/{guestConfigurationAssignmentName}"
	if guestConfigurationAssignmentName == "" {
		return nil, errors.New("parameter guestConfigurationAssignmentName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{guestConfigurationAssignmentName}", url.PathEscape(guestConfigurationAssignmentName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if vmName == "" {
		return nil, errors.New("parameter vmName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{vmName}", url.PathEscape(vmName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// createOrUpdateHandleResponse handles the CreateOrUpdate response.
func (client *GuestConfigurationAssignmentsClient) createOrUpdateHandleResponse(resp *http.Response) (GuestConfigurationAssignmentsCreateOrUpdateResponse, error) {
	result := GuestConfigurationAssignmentsCreateOrUpdateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.GuestConfigurationAssignment); err != nil {
		return GuestConfigurationAssignmentsCreateOrUpdateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// createOrUpdateHandleError handles the CreateOrUpdate error response.
func (client *GuestConfigurationAssignmentsClient) createOrUpdateHandleError(resp *http.Response) error {
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

// Delete - Delete a guest configuration assignment
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) Delete(ctx context.Context, resourceGroupName string, guestConfigurationAssignmentName string, vmName string, options *GuestConfigurationAssignmentsDeleteOptions) (GuestConfigurationAssignmentsDeleteResponse, error) {
	req, err := client.deleteCreateRequest(ctx, resourceGroupName, guestConfigurationAssignmentName, vmName, options)
	if err != nil {
		return GuestConfigurationAssignmentsDeleteResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsDeleteResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return GuestConfigurationAssignmentsDeleteResponse{}, client.deleteHandleError(resp)
	}
	return GuestConfigurationAssignmentsDeleteResponse{RawResponse: resp}, nil
}

// deleteCreateRequest creates the Delete request.
func (client *GuestConfigurationAssignmentsClient) deleteCreateRequest(ctx context.Context, resourceGroupName string, guestConfigurationAssignmentName string, vmName string, options *GuestConfigurationAssignmentsDeleteOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/{guestConfigurationAssignmentName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if guestConfigurationAssignmentName == "" {
		return nil, errors.New("parameter guestConfigurationAssignmentName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{guestConfigurationAssignmentName}", url.PathEscape(guestConfigurationAssignmentName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if vmName == "" {
		return nil, errors.New("parameter vmName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{vmName}", url.PathEscape(vmName))
	req, err := runtime.NewRequest(ctx, http.MethodDelete, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// deleteHandleError handles the Delete error response.
func (client *GuestConfigurationAssignmentsClient) deleteHandleError(resp *http.Response) error {
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

// Get - Get information about a guest configuration assignment
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) Get(ctx context.Context, resourceGroupName string, guestConfigurationAssignmentName string, vmName string, options *GuestConfigurationAssignmentsGetOptions) (GuestConfigurationAssignmentsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, resourceGroupName, guestConfigurationAssignmentName, vmName, options)
	if err != nil {
		return GuestConfigurationAssignmentsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return GuestConfigurationAssignmentsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *GuestConfigurationAssignmentsClient) getCreateRequest(ctx context.Context, resourceGroupName string, guestConfigurationAssignmentName string, vmName string, options *GuestConfigurationAssignmentsGetOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments/{guestConfigurationAssignmentName}"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if guestConfigurationAssignmentName == "" {
		return nil, errors.New("parameter guestConfigurationAssignmentName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{guestConfigurationAssignmentName}", url.PathEscape(guestConfigurationAssignmentName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if vmName == "" {
		return nil, errors.New("parameter vmName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{vmName}", url.PathEscape(vmName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *GuestConfigurationAssignmentsClient) getHandleResponse(resp *http.Response) (GuestConfigurationAssignmentsGetResponse, error) {
	result := GuestConfigurationAssignmentsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.GuestConfigurationAssignment); err != nil {
		return GuestConfigurationAssignmentsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *GuestConfigurationAssignmentsClient) getHandleError(resp *http.Response) error {
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

// List - List all guest configuration assignments for a virtual machine.
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) List(ctx context.Context, resourceGroupName string, vmName string, options *GuestConfigurationAssignmentsListOptions) (GuestConfigurationAssignmentsListResponse, error) {
	req, err := client.listCreateRequest(ctx, resourceGroupName, vmName, options)
	if err != nil {
		return GuestConfigurationAssignmentsListResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsListResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return GuestConfigurationAssignmentsListResponse{}, client.listHandleError(resp)
	}
	return client.listHandleResponse(resp)
}

// listCreateRequest creates the List request.
func (client *GuestConfigurationAssignmentsClient) listCreateRequest(ctx context.Context, resourceGroupName string, vmName string, options *GuestConfigurationAssignmentsListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
	if resourceGroupName == "" {
		return nil, errors.New("parameter resourceGroupName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{resourceGroupName}", url.PathEscape(resourceGroupName))
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	if vmName == "" {
		return nil, errors.New("parameter vmName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{vmName}", url.PathEscape(vmName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *GuestConfigurationAssignmentsClient) listHandleResponse(resp *http.Response) (GuestConfigurationAssignmentsListResponse, error) {
	result := GuestConfigurationAssignmentsListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.GuestConfigurationAssignmentList); err != nil {
		return GuestConfigurationAssignmentsListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *GuestConfigurationAssignmentsClient) listHandleError(resp *http.Response) error {
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

// RGList - List all guest configuration assignments for a resource group.
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) RGList(ctx context.Context, resourceGroupName string, options *GuestConfigurationAssignmentsRGListOptions) (GuestConfigurationAssignmentsRGListResponse, error) {
	req, err := client.rgListCreateRequest(ctx, resourceGroupName, options)
	if err != nil {
		return GuestConfigurationAssignmentsRGListResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsRGListResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return GuestConfigurationAssignmentsRGListResponse{}, client.rgListHandleError(resp)
	}
	return client.rgListHandleResponse(resp)
}

// rgListCreateRequest creates the RGList request.
func (client *GuestConfigurationAssignmentsClient) rgListCreateRequest(ctx context.Context, resourceGroupName string, options *GuestConfigurationAssignmentsRGListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
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
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// rgListHandleResponse handles the RGList response.
func (client *GuestConfigurationAssignmentsClient) rgListHandleResponse(resp *http.Response) (GuestConfigurationAssignmentsRGListResponse, error) {
	result := GuestConfigurationAssignmentsRGListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.GuestConfigurationAssignmentList); err != nil {
		return GuestConfigurationAssignmentsRGListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// rgListHandleError handles the RGList error response.
func (client *GuestConfigurationAssignmentsClient) rgListHandleError(resp *http.Response) error {
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

// SubscriptionList - List all guest configuration assignments for a subscription.
// If the operation fails it returns the *ErrorResponse error type.
func (client *GuestConfigurationAssignmentsClient) SubscriptionList(ctx context.Context, options *GuestConfigurationAssignmentsSubscriptionListOptions) (GuestConfigurationAssignmentsSubscriptionListResponse, error) {
	req, err := client.subscriptionListCreateRequest(ctx, options)
	if err != nil {
		return GuestConfigurationAssignmentsSubscriptionListResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return GuestConfigurationAssignmentsSubscriptionListResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK, http.StatusNoContent) {
		return GuestConfigurationAssignmentsSubscriptionListResponse{}, client.subscriptionListHandleError(resp)
	}
	return client.subscriptionListHandleResponse(resp)
}

// subscriptionListCreateRequest creates the SubscriptionList request.
func (client *GuestConfigurationAssignmentsClient) subscriptionListCreateRequest(ctx context.Context, options *GuestConfigurationAssignmentsSubscriptionListOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/providers/Microsoft.GuestConfiguration/guestConfigurationAssignments"
	if client.subscriptionID == "" {
		return nil, errors.New("parameter client.subscriptionID cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{subscriptionId}", url.PathEscape(client.subscriptionID))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-06-25")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// subscriptionListHandleResponse handles the SubscriptionList response.
func (client *GuestConfigurationAssignmentsClient) subscriptionListHandleResponse(resp *http.Response) (GuestConfigurationAssignmentsSubscriptionListResponse, error) {
	result := GuestConfigurationAssignmentsSubscriptionListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.GuestConfigurationAssignmentList); err != nil {
		return GuestConfigurationAssignmentsSubscriptionListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// subscriptionListHandleError handles the SubscriptionList error response.
func (client *GuestConfigurationAssignmentsClient) subscriptionListHandleError(resp *http.Response) error {
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
