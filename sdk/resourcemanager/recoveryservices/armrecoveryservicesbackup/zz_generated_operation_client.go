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

// OperationClient contains the methods for the Operation group.
// Don't use this type directly, use NewOperationClient() instead.
type OperationClient struct {
	ep             string
	pl             runtime.Pipeline
	subscriptionID string
}

// NewOperationClient creates a new instance of OperationClient with the specified values.
func NewOperationClient(subscriptionID string, credential azcore.TokenCredential, options *arm.ClientOptions) *OperationClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &OperationClient{subscriptionID: subscriptionID, ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Validate - Validate operation for specified backed up item. This is a synchronous operation.
// If the operation fails it returns the *CloudError error type.
func (client *OperationClient) Validate(ctx context.Context, vaultName string, resourceGroupName string, parameters ValidateOperationRequestClassification, options *OperationValidateOptions) (OperationValidateResponse, error) {
	req, err := client.validateCreateRequest(ctx, vaultName, resourceGroupName, parameters, options)
	if err != nil {
		return OperationValidateResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return OperationValidateResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return OperationValidateResponse{}, client.validateHandleError(resp)
	}
	return client.validateHandleResponse(resp)
}

// validateCreateRequest creates the Validate request.
func (client *OperationClient) validateCreateRequest(ctx context.Context, vaultName string, resourceGroupName string, parameters ValidateOperationRequestClassification, options *OperationValidateOptions) (*policy.Request, error) {
	urlPath := "/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.RecoveryServices/vaults/{vaultName}/backupValidateOperation"
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
func (client *OperationClient) validateHandleResponse(resp *http.Response) (OperationValidateResponse, error) {
	result := OperationValidateResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.ValidateOperationsResponse); err != nil {
		return OperationValidateResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// validateHandleError handles the Validate error response.
func (client *OperationClient) validateHandleError(resp *http.Response) error {
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
