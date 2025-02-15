//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armquota

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

// QuotaRequestStatusClient contains the methods for the QuotaRequestStatus group.
// Don't use this type directly, use NewQuotaRequestStatusClient() instead.
type QuotaRequestStatusClient struct {
	ep string
	pl runtime.Pipeline
}

// NewQuotaRequestStatusClient creates a new instance of QuotaRequestStatusClient with the specified values.
func NewQuotaRequestStatusClient(credential azcore.TokenCredential, options *arm.ClientOptions) *QuotaRequestStatusClient {
	cp := arm.ClientOptions{}
	if options != nil {
		cp = *options
	}
	if len(cp.Host) == 0 {
		cp.Host = arm.AzurePublicCloud
	}
	return &QuotaRequestStatusClient{ep: string(cp.Host), pl: armruntime.NewPipeline(module, version, credential, &cp)}
}

// Get - Get the quota request details and status by quota request ID for the resources of the resource provider at a specific location. The quota request
// ID id is returned in the response of the PUT
// operation.
// If the operation fails it returns the *ExceptionResponse error type.
func (client *QuotaRequestStatusClient) Get(ctx context.Context, id string, scope string, options *QuotaRequestStatusGetOptions) (QuotaRequestStatusGetResponse, error) {
	req, err := client.getCreateRequest(ctx, id, scope, options)
	if err != nil {
		return QuotaRequestStatusGetResponse{}, err
	}
	resp, err := client.pl.Do(req)
	if err != nil {
		return QuotaRequestStatusGetResponse{}, err
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		return QuotaRequestStatusGetResponse{}, client.getHandleError(resp)
	}
	return client.getHandleResponse(resp)
}

// getCreateRequest creates the Get request.
func (client *QuotaRequestStatusClient) getCreateRequest(ctx context.Context, id string, scope string, options *QuotaRequestStatusGetOptions) (*policy.Request, error) {
	urlPath := "/{scope}/providers/Microsoft.Quota/quotaRequests/{id}"
	if id == "" {
		return nil, errors.New("parameter id cannot be empty")
	}
	urlPath = strings.ReplaceAll(urlPath, "{id}", url.PathEscape(id))
	urlPath = strings.ReplaceAll(urlPath, "{scope}", scope)
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-15-preview")
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// getHandleResponse handles the Get response.
func (client *QuotaRequestStatusClient) getHandleResponse(resp *http.Response) (QuotaRequestStatusGetResponse, error) {
	result := QuotaRequestStatusGetResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.QuotaRequestDetails); err != nil {
		return QuotaRequestStatusGetResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// getHandleError handles the Get error response.
func (client *QuotaRequestStatusClient) getHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ExceptionResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}

// List - For the specified scope, get the current quota requests for a one year period ending at the time is made. Use the oData filter to select quota
// requests.
// If the operation fails it returns the *ExceptionResponse error type.
func (client *QuotaRequestStatusClient) List(scope string, options *QuotaRequestStatusListOptions) *QuotaRequestStatusListPager {
	return &QuotaRequestStatusListPager{
		client: client,
		requester: func(ctx context.Context) (*policy.Request, error) {
			return client.listCreateRequest(ctx, scope, options)
		},
		advancer: func(ctx context.Context, resp QuotaRequestStatusListResponse) (*policy.Request, error) {
			return runtime.NewRequest(ctx, http.MethodGet, *resp.QuotaRequestDetailsList.NextLink)
		},
	}
}

// listCreateRequest creates the List request.
func (client *QuotaRequestStatusClient) listCreateRequest(ctx context.Context, scope string, options *QuotaRequestStatusListOptions) (*policy.Request, error) {
	urlPath := "/{scope}/providers/Microsoft.Quota/quotaRequests"
	urlPath = strings.ReplaceAll(urlPath, "{scope}", scope)
	req, err := runtime.NewRequest(ctx, http.MethodGet, runtime.JoinPaths(client.ep, urlPath))
	if err != nil {
		return nil, err
	}
	reqQP := req.Raw().URL.Query()
	reqQP.Set("api-version", "2021-03-15-preview")
	if options != nil && options.Filter != nil {
		reqQP.Set("$filter", *options.Filter)
	}
	if options != nil && options.Top != nil {
		reqQP.Set("$top", strconv.FormatInt(int64(*options.Top), 10))
	}
	if options != nil && options.Skiptoken != nil {
		reqQP.Set("$skiptoken", *options.Skiptoken)
	}
	req.Raw().URL.RawQuery = reqQP.Encode()
	req.Raw().Header.Set("Accept", "application/json")
	return req, nil
}

// listHandleResponse handles the List response.
func (client *QuotaRequestStatusClient) listHandleResponse(resp *http.Response) (QuotaRequestStatusListResponse, error) {
	result := QuotaRequestStatusListResponse{RawResponse: resp}
	if err := runtime.UnmarshalAsJSON(resp, &result.QuotaRequestDetailsList); err != nil {
		return QuotaRequestStatusListResponse{}, runtime.NewResponseError(err, resp)
	}
	return result, nil
}

// listHandleError handles the List error response.
func (client *QuotaRequestStatusClient) listHandleError(resp *http.Response) error {
	body, err := runtime.Payload(resp)
	if err != nil {
		return runtime.NewResponseError(err, resp)
	}
	errType := ExceptionResponse{raw: string(body)}
	if err := runtime.UnmarshalAsJSON(resp, &errType); err != nil {
		return runtime.NewResponseError(fmt.Errorf("%s\n%s", string(body), err), resp)
	}
	return runtime.NewResponseError(&errType, resp)
}
