//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armcontainerinstance

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
)

// ContainerGroupsCreateOrUpdatePoller provides polling facilities until the operation reaches a terminal state.
type ContainerGroupsCreateOrUpdatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *ContainerGroupsCreateOrUpdatePoller) Done() bool {
	return p.pt.Done()
}

// Poll fetches the latest state of the LRO.  It returns an HTTP response or error.
// If the LRO has completed successfully, the poller's state is updated and the HTTP
// response is returned.
// If the LRO has completed with failure or was cancelled, the poller's state is
// updated and the error is returned.
// If the LRO has not reached a terminal state, the poller's state is updated and
// the latest HTTP response is returned.
// If Poll fails, the poller's state is unmodified and the error is returned.
// Calling Poll on an LRO that has reached a terminal state will return the final
// HTTP response or error.
func (p *ContainerGroupsCreateOrUpdatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final ContainerGroupsCreateOrUpdateResponse will be returned.
func (p *ContainerGroupsCreateOrUpdatePoller) FinalResponse(ctx context.Context) (ContainerGroupsCreateOrUpdateResponse, error) {
	respType := ContainerGroupsCreateOrUpdateResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.ContainerGroup)
	if err != nil {
		return ContainerGroupsCreateOrUpdateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *ContainerGroupsCreateOrUpdatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// ContainerGroupsDeletePoller provides polling facilities until the operation reaches a terminal state.
type ContainerGroupsDeletePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *ContainerGroupsDeletePoller) Done() bool {
	return p.pt.Done()
}

// Poll fetches the latest state of the LRO.  It returns an HTTP response or error.
// If the LRO has completed successfully, the poller's state is updated and the HTTP
// response is returned.
// If the LRO has completed with failure or was cancelled, the poller's state is
// updated and the error is returned.
// If the LRO has not reached a terminal state, the poller's state is updated and
// the latest HTTP response is returned.
// If Poll fails, the poller's state is unmodified and the error is returned.
// Calling Poll on an LRO that has reached a terminal state will return the final
// HTTP response or error.
func (p *ContainerGroupsDeletePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final ContainerGroupsDeleteResponse will be returned.
func (p *ContainerGroupsDeletePoller) FinalResponse(ctx context.Context) (ContainerGroupsDeleteResponse, error) {
	respType := ContainerGroupsDeleteResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.ContainerGroup)
	if err != nil {
		return ContainerGroupsDeleteResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *ContainerGroupsDeletePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// ContainerGroupsRestartPoller provides polling facilities until the operation reaches a terminal state.
type ContainerGroupsRestartPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *ContainerGroupsRestartPoller) Done() bool {
	return p.pt.Done()
}

// Poll fetches the latest state of the LRO.  It returns an HTTP response or error.
// If the LRO has completed successfully, the poller's state is updated and the HTTP
// response is returned.
// If the LRO has completed with failure or was cancelled, the poller's state is
// updated and the error is returned.
// If the LRO has not reached a terminal state, the poller's state is updated and
// the latest HTTP response is returned.
// If Poll fails, the poller's state is unmodified and the error is returned.
// Calling Poll on an LRO that has reached a terminal state will return the final
// HTTP response or error.
func (p *ContainerGroupsRestartPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final ContainerGroupsRestartResponse will be returned.
func (p *ContainerGroupsRestartPoller) FinalResponse(ctx context.Context) (ContainerGroupsRestartResponse, error) {
	respType := ContainerGroupsRestartResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return ContainerGroupsRestartResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *ContainerGroupsRestartPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// ContainerGroupsStartPoller provides polling facilities until the operation reaches a terminal state.
type ContainerGroupsStartPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *ContainerGroupsStartPoller) Done() bool {
	return p.pt.Done()
}

// Poll fetches the latest state of the LRO.  It returns an HTTP response or error.
// If the LRO has completed successfully, the poller's state is updated and the HTTP
// response is returned.
// If the LRO has completed with failure or was cancelled, the poller's state is
// updated and the error is returned.
// If the LRO has not reached a terminal state, the poller's state is updated and
// the latest HTTP response is returned.
// If Poll fails, the poller's state is unmodified and the error is returned.
// Calling Poll on an LRO that has reached a terminal state will return the final
// HTTP response or error.
func (p *ContainerGroupsStartPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final ContainerGroupsStartResponse will be returned.
func (p *ContainerGroupsStartPoller) FinalResponse(ctx context.Context) (ContainerGroupsStartResponse, error) {
	respType := ContainerGroupsStartResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return ContainerGroupsStartResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *ContainerGroupsStartPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}
