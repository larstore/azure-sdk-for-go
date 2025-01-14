//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armbilling

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

// InstructionsClient contains the methods for the Instructions group.
// Don't use this type directly, use NewInstructionsClient() instead.
type InstructionsClient struct {
	ep string
	pl runtime.Pipeline
}

// NewInstructionsClient creates a new instance of InstructionsClient with the specified values.
func NewInstructionsClient(credential azcore.TokenCredential, options *arm.ClientOptions) *InstructionsClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &InstructionsClient{ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Get - Get the instruction by name. These are custom billing instructions and are only applicable for certain customers.
// If the operation fails it returns the *ErrorResponse error type.
func (client *InstructionsClient) Get(ctx context.Context, billingAccountName string, billingProfileName string, instructionName string, options *InstructionsGetOptions) (InstructionsGetResponse, error) {
	req, err := client.getCreateRequest(ctx, billingAccountName, billingProfileName, instructionName, options)
	if err != nil {
		return InstructionsGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return InstructionsGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return InstructionsGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *InstructionsClient) getCreateRequest(ctx context.Context, billingAccountName string, billingProfileName string, instructionName string, options *InstructionsGetOptions) (*policy.Request, error) {
	urlPath := "/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/instructions/{instructionName}"
	if billingAccountName == "" {
		return nil, errors.New("parameter billingAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingAccountName}", url.PathEscape(billingAccountName))
	if billingProfileName == "" {
		return nil, errors.New("parameter billingProfileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingProfileName}", url.PathEscape(billingProfileName))
	if instructionName == "" {
		return nil, errors.New("parameter instructionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{instructionName}", url.PathEscape(instructionName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-05-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *InstructionsClient) getHandleResponse(resp *http.Response) (InstructionsGetResponse, error) {
	result := InstructionsGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Instruction); err != nil {
		return InstructionsGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *InstructionsClient) getHandleError(resp *http.Response) error {
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

// ListByBillingProfile - Lists the instructions by billing profile id.
// If the operation fails it returns the *ErrorResponse error type.
func (client *InstructionsClient) ListByBillingProfile(billingAccountName string, billingProfileName string, options *InstructionsListByBillingProfileOptions) *InstructionsListByBillingProfilePager {
	return &InstructionsListByBillingProfilePager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listByBillingProfileCreateRequest(ctx, billingAccountName, billingProfileName, options)
		},
		advancer: func(ctx context.Context, resp InstructionsListByBillingProfileResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.InstructionListResult.NextLink)
		},
	}
}

// listByBillingProfileCreateRequest creates the ListByBillingProfile request.
func (client *InstructionsClient) listByBillingProfileCreateRequest(ctx context.Context, billingAccountName string, billingProfileName string, options *InstructionsListByBillingProfileOptions) (*policy.Request, error) {
	urlPath := "/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/instructions"
	if billingAccountName == "" {
		return nil, errors.New("parameter billingAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingAccountName}", url.PathEscape(billingAccountName))
	if billingProfileName == "" {
		return nil, errors.New("parameter billingProfileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingProfileName}", url.PathEscape(billingProfileName))
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-05-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listByBillingProfileHandleResponse handles the ListByBillingProfile response.
func (client *InstructionsClient) listByBillingProfileHandleResponse(resp *http.Response) (InstructionsListByBillingProfileResponse, error) {
	result := InstructionsListByBillingProfileResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.InstructionListResult); err != nil {
		return InstructionsListByBillingProfileResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listByBillingProfileHandleError handles the ListByBillingProfile error response.
func (client *InstructionsClient) listByBillingProfileHandleError(resp *http.Response) error {
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

// Put - Creates or updates an instruction. These are custom billing instructions and are only applicable for certain customers.
// If the operation fails it returns the *ErrorResponse error type.
func (client *InstructionsClient) Put(ctx context.Context, billingAccountName string, billingProfileName string, instructionName string, parameters Instruction, options *InstructionsPutOptions) (InstructionsPutResponse, error) {
	req, err := client.putCreateRequest(ctx, billingAccountName, billingProfileName, instructionName, parameters, options)
	if err != nil {
		return InstructionsPutResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return InstructionsPutResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return InstructionsPutResponse{}, client.putHandleError(resp)
	}
	return client.putHandleResponse(resp)
}

// putCreateRequest creates the Put request.
func (client *InstructionsClient) putCreateRequest(ctx context.Context, billingAccountName string, billingProfileName string, instructionName string, parameters Instruction, options *InstructionsPutOptions) (*policy.Request, error) {
	urlPath := "/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/billingProfiles/{billingProfileName}/instructions/{instructionName}"
	if billingAccountName == "" {
		return nil, errors.New("parameter billingAccountName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingAccountName}", url.PathEscape(billingAccountName))
	if billingProfileName == "" {
		return nil, errors.New("parameter billingProfileName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{billingProfileName}", url.PathEscape(billingProfileName))
	if instructionName == "" {
		return nil, errors.New("parameter instructionName cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{instructionName}", url.PathEscape(instructionName))
	req, err := runtime.NewRequest(ctx, http.MethodPut, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2020-05-01")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, runtime.MarshalAsJSON(req, parameters)
}

// putHandleResponse handles the Put response.
func (client *InstructionsClient) putHandleResponse(resp *http.Response) (InstructionsPutResponse, error) {
	result := InstructionsPutResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.Instruction); err != nil {
		return InstructionsPutResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// putHandleError handles the Put error response.
func (client *InstructionsClient) putHandleError(resp *http.Response) error {
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
