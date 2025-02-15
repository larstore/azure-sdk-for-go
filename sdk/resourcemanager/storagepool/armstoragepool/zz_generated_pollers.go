//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armstoragepool

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
)

// DiskPoolsCreateOrUpdatePoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsCreateOrUpdatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsCreateOrUpdatePoller) Done() bool {
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
func (p *DiskPoolsCreateOrUpdatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsCreateOrUpdateResponse will be returned.
func (p *DiskPoolsCreateOrUpdatePoller) FinalResponse(ctx context.Context) (DiskPoolsCreateOrUpdateResponse, error) {
	respType := DiskPoolsCreateOrUpdateResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.DiskPool)
	if err != nil {
		return DiskPoolsCreateOrUpdateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsCreateOrUpdatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// DiskPoolsDeallocatePoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsDeallocatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsDeallocatePoller) Done() bool {
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
func (p *DiskPoolsDeallocatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsDeallocateResponse will be returned.
func (p *DiskPoolsDeallocatePoller) FinalResponse(ctx context.Context) (DiskPoolsDeallocateResponse, error) {
	respType := DiskPoolsDeallocateResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return DiskPoolsDeallocateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsDeallocatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// DiskPoolsDeletePoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsDeletePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsDeletePoller) Done() bool {
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
func (p *DiskPoolsDeletePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsDeleteResponse will be returned.
func (p *DiskPoolsDeletePoller) FinalResponse(ctx context.Context) (DiskPoolsDeleteResponse, error) {
	respType := DiskPoolsDeleteResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return DiskPoolsDeleteResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsDeletePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// DiskPoolsStartPoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsStartPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsStartPoller) Done() bool {
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
func (p *DiskPoolsStartPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsStartResponse will be returned.
func (p *DiskPoolsStartPoller) FinalResponse(ctx context.Context) (DiskPoolsStartResponse, error) {
	respType := DiskPoolsStartResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return DiskPoolsStartResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsStartPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// DiskPoolsUpdatePoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsUpdatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsUpdatePoller) Done() bool {
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
func (p *DiskPoolsUpdatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsUpdateResponse will be returned.
func (p *DiskPoolsUpdatePoller) FinalResponse(ctx context.Context) (DiskPoolsUpdateResponse, error) {
	respType := DiskPoolsUpdateResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.DiskPool)
	if err != nil {
		return DiskPoolsUpdateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsUpdatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// DiskPoolsUpgradePoller provides polling facilities until the operation reaches a terminal state.
type DiskPoolsUpgradePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *DiskPoolsUpgradePoller) Done() bool {
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
func (p *DiskPoolsUpgradePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final DiskPoolsUpgradeResponse will be returned.
func (p *DiskPoolsUpgradePoller) FinalResponse(ctx context.Context) (DiskPoolsUpgradeResponse, error) {
	respType := DiskPoolsUpgradeResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return DiskPoolsUpgradeResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *DiskPoolsUpgradePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// IscsiTargetsCreateOrUpdatePoller provides polling facilities until the operation reaches a terminal state.
type IscsiTargetsCreateOrUpdatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *IscsiTargetsCreateOrUpdatePoller) Done() bool {
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
func (p *IscsiTargetsCreateOrUpdatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final IscsiTargetsCreateOrUpdateResponse will be returned.
func (p *IscsiTargetsCreateOrUpdatePoller) FinalResponse(ctx context.Context) (IscsiTargetsCreateOrUpdateResponse, error) {
	respType := IscsiTargetsCreateOrUpdateResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.IscsiTarget)
	if err != nil {
		return IscsiTargetsCreateOrUpdateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *IscsiTargetsCreateOrUpdatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// IscsiTargetsDeletePoller provides polling facilities until the operation reaches a terminal state.
type IscsiTargetsDeletePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *IscsiTargetsDeletePoller) Done() bool {
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
func (p *IscsiTargetsDeletePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final IscsiTargetsDeleteResponse will be returned.
func (p *IscsiTargetsDeletePoller) FinalResponse(ctx context.Context) (IscsiTargetsDeleteResponse, error) {
	respType := IscsiTargetsDeleteResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return IscsiTargetsDeleteResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *IscsiTargetsDeletePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// IscsiTargetsUpdatePoller provides polling facilities until the operation reaches a terminal state.
type IscsiTargetsUpdatePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *IscsiTargetsUpdatePoller) Done() bool {
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
func (p *IscsiTargetsUpdatePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final IscsiTargetsUpdateResponse will be returned.
func (p *IscsiTargetsUpdatePoller) FinalResponse(ctx context.Context) (IscsiTargetsUpdateResponse, error) {
	respType := IscsiTargetsUpdateResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.IscsiTarget)
	if err != nil {
		return IscsiTargetsUpdateResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *IscsiTargetsUpdatePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}
