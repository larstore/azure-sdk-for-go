//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armquantum

import (
	"context"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"net/http"
	"time"
)

// OfferingsListResponse contains the response from method Offerings.List.
type OfferingsListResponse struct {
	OfferingsListResultEnvelope
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// OfferingsListResultEnvelope contains the result from method Offerings.List.
type OfferingsListResultEnvelope struct {
	OfferingsListResult
}

// OperationsListResponse contains the response from method Operations.List.
type OperationsListResponse struct {
	OperationsListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// OperationsListResult contains the result from method Operations.List.
type OperationsListResult struct {
	OperationsList
}

// WorkspaceCheckNameAvailabilityResponse contains the response from method Workspace.CheckNameAvailability.
type WorkspaceCheckNameAvailabilityResponse struct {
	WorkspaceCheckNameAvailabilityResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspaceCheckNameAvailabilityResult contains the result from method Workspace.CheckNameAvailability.
type WorkspaceCheckNameAvailabilityResult struct {
	CheckNameAvailabilityResult
}

// WorkspacesCreateOrUpdatePollerResponse contains the response from method Workspaces.CreateOrUpdate.
type WorkspacesCreateOrUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesCreateOrUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesCreateOrUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesCreateOrUpdateResponse, error) {
	respType := WorkspacesCreateOrUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.QuantumWorkspace)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesCreateOrUpdatePollerResponse from the provided client and resume token.
func (l *WorkspacesCreateOrUpdatePollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.CreateOrUpdate", token, client.pl, client.createOrUpdateHandleError)
	if err != nil {
		return err
	}
	poller := &WorkspacesCreateOrUpdatePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// WorkspacesCreateOrUpdateResponse contains the response from method Workspaces.CreateOrUpdate.
type WorkspacesCreateOrUpdateResponse struct {
	WorkspacesCreateOrUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesCreateOrUpdateResult contains the result from method Workspaces.CreateOrUpdate.
type WorkspacesCreateOrUpdateResult struct {
	QuantumWorkspace
}

// WorkspacesDeletePollerResponse contains the response from method Workspaces.Delete.
type WorkspacesDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *WorkspacesDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l WorkspacesDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (WorkspacesDeleteResponse, error) {
	respType := WorkspacesDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a WorkspacesDeletePollerResponse from the provided client and resume token.
func (l *WorkspacesDeletePollerResponse) Resume(ctx context.Context, client *WorkspacesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("WorkspacesClient.Delete", token, client.pl, client.deleteHandleError)
	if err != nil {
		return err
	}
	poller := &WorkspacesDeletePoller{
		pt: pt,
	}
	resp, err := poller.Poll(ctx)
	if err != nil {
		return err
	}
	l.Poller = poller
	l.RawResponse = resp
	return nil
}

// WorkspacesDeleteResponse contains the response from method Workspaces.Delete.
type WorkspacesDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesGetResponse contains the response from method Workspaces.Get.
type WorkspacesGetResponse struct {
	WorkspacesGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesGetResult contains the result from method Workspaces.Get.
type WorkspacesGetResult struct {
	QuantumWorkspace
}

// WorkspacesListByResourceGroupResponse contains the response from method Workspaces.ListByResourceGroup.
type WorkspacesListByResourceGroupResponse struct {
	WorkspacesListByResourceGroupResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesListByResourceGroupResult contains the result from method Workspaces.ListByResourceGroup.
type WorkspacesListByResourceGroupResult struct {
	WorkspaceListResult
}

// WorkspacesListBySubscriptionResponse contains the response from method Workspaces.ListBySubscription.
type WorkspacesListBySubscriptionResponse struct {
	WorkspacesListBySubscriptionResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesListBySubscriptionResult contains the result from method Workspaces.ListBySubscription.
type WorkspacesListBySubscriptionResult struct {
	WorkspaceListResult
}

// WorkspacesUpdateTagsResponse contains the response from method Workspaces.UpdateTags.
type WorkspacesUpdateTagsResponse struct {
	WorkspacesUpdateTagsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// WorkspacesUpdateTagsResult contains the result from method Workspaces.UpdateTags.
type WorkspacesUpdateTagsResult struct {
	QuantumWorkspace
}
