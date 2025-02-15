//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armpowerbidedicated

import (
	"context"
	armruntime "github.com/Azure/azure-sdk-for-go/sdk/azcore/arm/runtime"
	"net/http"
	"time"
)

// AutoScaleVCoresCreateResponse contains the response from method AutoScaleVCores.Create.
type AutoScaleVCoresCreateResponse struct {
	AutoScaleVCoresCreateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresCreateResult contains the result from method AutoScaleVCores.Create.
type AutoScaleVCoresCreateResult struct {
	AutoScaleVCore
}

// AutoScaleVCoresDeleteResponse contains the response from method AutoScaleVCores.Delete.
type AutoScaleVCoresDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresGetResponse contains the response from method AutoScaleVCores.Get.
type AutoScaleVCoresGetResponse struct {
	AutoScaleVCoresGetResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresGetResult contains the result from method AutoScaleVCores.Get.
type AutoScaleVCoresGetResult struct {
	AutoScaleVCore
}

// AutoScaleVCoresListByResourceGroupResponse contains the response from method AutoScaleVCores.ListByResourceGroup.
type AutoScaleVCoresListByResourceGroupResponse struct {
	AutoScaleVCoresListByResourceGroupResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresListByResourceGroupResult contains the result from method AutoScaleVCores.ListByResourceGroup.
type AutoScaleVCoresListByResourceGroupResult struct {
	AutoScaleVCoreListResult
}

// AutoScaleVCoresListBySubscriptionResponse contains the response from method AutoScaleVCores.ListBySubscription.
type AutoScaleVCoresListBySubscriptionResponse struct {
	AutoScaleVCoresListBySubscriptionResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresListBySubscriptionResult contains the result from method AutoScaleVCores.ListBySubscription.
type AutoScaleVCoresListBySubscriptionResult struct {
	AutoScaleVCoreListResult
}

// AutoScaleVCoresUpdateResponse contains the response from method AutoScaleVCores.Update.
type AutoScaleVCoresUpdateResponse struct {
	AutoScaleVCoresUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// AutoScaleVCoresUpdateResult contains the result from method AutoScaleVCores.Update.
type AutoScaleVCoresUpdateResult struct {
	AutoScaleVCore
}

// CapacitiesCheckNameAvailabilityResponse contains the response from method Capacities.CheckNameAvailability.
type CapacitiesCheckNameAvailabilityResponse struct {
	CapacitiesCheckNameAvailabilityResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesCheckNameAvailabilityResult contains the result from method Capacities.CheckNameAvailability.
type CapacitiesCheckNameAvailabilityResult struct {
	CheckCapacityNameAvailabilityResult
}

// CapacitiesCreatePollerResponse contains the response from method Capacities.Create.
type CapacitiesCreatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *CapacitiesCreatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l CapacitiesCreatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (CapacitiesCreateResponse, error) {
	respType := CapacitiesCreateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.DedicatedCapacity)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a CapacitiesCreatePollerResponse from the provided client and resume token.
func (l *CapacitiesCreatePollerResponse) Resume(ctx context.Context, client *CapacitiesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("CapacitiesClient.Create", token, client.pl, client.createHandleError)
	if err != nil {
		return err
	}
	poller := &CapacitiesCreatePoller{
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

// CapacitiesCreateResponse contains the response from method Capacities.Create.
type CapacitiesCreateResponse struct {
	CapacitiesCreateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesCreateResult contains the result from method Capacities.Create.
type CapacitiesCreateResult struct {
	DedicatedCapacity
}

// CapacitiesDeletePollerResponse contains the response from method Capacities.Delete.
type CapacitiesDeletePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *CapacitiesDeletePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l CapacitiesDeletePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (CapacitiesDeleteResponse, error) {
	respType := CapacitiesDeleteResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a CapacitiesDeletePollerResponse from the provided client and resume token.
func (l *CapacitiesDeletePollerResponse) Resume(ctx context.Context, client *CapacitiesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("CapacitiesClient.Delete", token, client.pl, client.deleteHandleError)
	if err != nil {
		return err
	}
	poller := &CapacitiesDeletePoller{
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

// CapacitiesDeleteResponse contains the response from method Capacities.Delete.
type CapacitiesDeleteResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesGetDetailsResponse contains the response from method Capacities.GetDetails.
type CapacitiesGetDetailsResponse struct {
	CapacitiesGetDetailsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesGetDetailsResult contains the result from method Capacities.GetDetails.
type CapacitiesGetDetailsResult struct {
	DedicatedCapacity
}

// CapacitiesListByResourceGroupResponse contains the response from method Capacities.ListByResourceGroup.
type CapacitiesListByResourceGroupResponse struct {
	CapacitiesListByResourceGroupResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesListByResourceGroupResult contains the result from method Capacities.ListByResourceGroup.
type CapacitiesListByResourceGroupResult struct {
	DedicatedCapacities
}

// CapacitiesListResponse contains the response from method Capacities.List.
type CapacitiesListResponse struct {
	CapacitiesListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesListResult contains the result from method Capacities.List.
type CapacitiesListResult struct {
	DedicatedCapacities
}

// CapacitiesListSKUsForCapacityResponse contains the response from method Capacities.ListSKUsForCapacity.
type CapacitiesListSKUsForCapacityResponse struct {
	CapacitiesListSKUsForCapacityResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesListSKUsForCapacityResult contains the result from method Capacities.ListSKUsForCapacity.
type CapacitiesListSKUsForCapacityResult struct {
	SKUEnumerationForExistingResourceResult
}

// CapacitiesListSKUsResponse contains the response from method Capacities.ListSKUs.
type CapacitiesListSKUsResponse struct {
	CapacitiesListSKUsResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesListSKUsResult contains the result from method Capacities.ListSKUs.
type CapacitiesListSKUsResult struct {
	SKUEnumerationForNewResourceResult
}

// CapacitiesResumePollerResponse contains the response from method Capacities.Resume.
type CapacitiesResumePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *CapacitiesResumePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l CapacitiesResumePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (CapacitiesResumeResponse, error) {
	respType := CapacitiesResumeResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a CapacitiesResumePollerResponse from the provided client and resume token.
func (l *CapacitiesResumePollerResponse) Resume(ctx context.Context, client *CapacitiesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("CapacitiesClient.Resume", token, client.pl, client.resumeHandleError)
	if err != nil {
		return err
	}
	poller := &CapacitiesResumePoller{
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

// CapacitiesResumeResponse contains the response from method Capacities.Resume.
type CapacitiesResumeResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesSuspendPollerResponse contains the response from method Capacities.Suspend.
type CapacitiesSuspendPollerResponse struct {
	// Poller contains an initialized poller.
	Poller *CapacitiesSuspendPoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l CapacitiesSuspendPollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (CapacitiesSuspendResponse, error) {
	respType := CapacitiesSuspendResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, nil)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a CapacitiesSuspendPollerResponse from the provided client and resume token.
func (l *CapacitiesSuspendPollerResponse) Resume(ctx context.Context, client *CapacitiesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("CapacitiesClient.Suspend", token, client.pl, client.suspendHandleError)
	if err != nil {
		return err
	}
	poller := &CapacitiesSuspendPoller{
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

// CapacitiesSuspendResponse contains the response from method Capacities.Suspend.
type CapacitiesSuspendResponse struct {
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesUpdatePollerResponse contains the response from method Capacities.Update.
type CapacitiesUpdatePollerResponse struct {
	// Poller contains an initialized poller.
	Poller *CapacitiesUpdatePoller

	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// PollUntilDone will poll the service endpoint until a terminal state is reached or an error is received.
// freq: the time to wait between intervals in absence of a Retry-After header. Allowed minimum is one second.
// A good starting value is 30 seconds. Note that some resources might benefit from a different value.
func (l CapacitiesUpdatePollerResponse) PollUntilDone(ctx context.Context, freq time.Duration) (CapacitiesUpdateResponse, error) {
	respType := CapacitiesUpdateResponse{}
	resp, err := l.Poller.pt.PollUntilDone(ctx, freq, &respType.DedicatedCapacity)
	if err != nil {
		return respType, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// Resume rehydrates a CapacitiesUpdatePollerResponse from the provided client and resume token.
func (l *CapacitiesUpdatePollerResponse) Resume(ctx context.Context, client *CapacitiesClient, token string) error {
	pt, err := armruntime.NewPollerFromResumeToken("CapacitiesClient.Update", token, client.pl, client.updateHandleError)
	if err != nil {
		return err
	}
	poller := &CapacitiesUpdatePoller{
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

// CapacitiesUpdateResponse contains the response from method Capacities.Update.
type CapacitiesUpdateResponse struct {
	CapacitiesUpdateResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// CapacitiesUpdateResult contains the result from method Capacities.Update.
type CapacitiesUpdateResult struct {
	DedicatedCapacity
}

// OperationsListResponse contains the response from method Operations.List.
type OperationsListResponse struct {
	OperationsListResult
	// RawResponse contains the underlying HTTP response.
	RawResponse *http.Response
}

// OperationsListResult contains the result from method Operations.List.
type OperationsListResult struct {
	OperationListResult
}
