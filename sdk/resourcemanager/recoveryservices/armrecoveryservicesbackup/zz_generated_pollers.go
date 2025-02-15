//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armrecoveryservicesbackup

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"net/http"
)

// PrivateEndpointConnectionDeletePoller provides polling facilities until the operation reaches a terminal state.
type PrivateEndpointConnectionDeletePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *PrivateEndpointConnectionDeletePoller) Done() bool {
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
func (p *PrivateEndpointConnectionDeletePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final PrivateEndpointConnectionDeleteResponse will be returned.
func (p *PrivateEndpointConnectionDeletePoller) FinalResponse(ctx context.Context) (PrivateEndpointConnectionDeleteResponse, error) {
	respType := PrivateEndpointConnectionDeleteResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return PrivateEndpointConnectionDeleteResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *PrivateEndpointConnectionDeletePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// PrivateEndpointConnectionPutPoller provides polling facilities until the operation reaches a terminal state.
type PrivateEndpointConnectionPutPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *PrivateEndpointConnectionPutPoller) Done() bool {
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
func (p *PrivateEndpointConnectionPutPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final PrivateEndpointConnectionPutResponse will be returned.
func (p *PrivateEndpointConnectionPutPoller) FinalResponse(ctx context.Context) (PrivateEndpointConnectionPutResponse, error) {
	respType := PrivateEndpointConnectionPutResponse{}
	resp, err := p.pt.FinalResponse(ctx, &respType.PrivateEndpointConnectionResource)
	if err != nil {
		return PrivateEndpointConnectionPutResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *PrivateEndpointConnectionPutPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// ProtectionPoliciesDeletePoller provides polling facilities until the operation reaches a terminal state.
type ProtectionPoliciesDeletePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *ProtectionPoliciesDeletePoller) Done() bool {
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
func (p *ProtectionPoliciesDeletePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final ProtectionPoliciesDeleteResponse will be returned.
func (p *ProtectionPoliciesDeletePoller) FinalResponse(ctx context.Context) (ProtectionPoliciesDeleteResponse, error) {
	respType := ProtectionPoliciesDeleteResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return ProtectionPoliciesDeleteResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *ProtectionPoliciesDeletePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// RecoveryServicesBackupClientBMSPrepareDataMovePoller provides polling facilities until the operation reaches a terminal state.
type RecoveryServicesBackupClientBMSPrepareDataMovePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *RecoveryServicesBackupClientBMSPrepareDataMovePoller) Done() bool {
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
func (p *RecoveryServicesBackupClientBMSPrepareDataMovePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final RecoveryServicesBackupClientBMSPrepareDataMoveResponse will be returned.
func (p *RecoveryServicesBackupClientBMSPrepareDataMovePoller) FinalResponse(ctx context.Context) (RecoveryServicesBackupClientBMSPrepareDataMoveResponse, error) {
	respType := RecoveryServicesBackupClientBMSPrepareDataMoveResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return RecoveryServicesBackupClientBMSPrepareDataMoveResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *RecoveryServicesBackupClientBMSPrepareDataMovePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// RecoveryServicesBackupClientBMSTriggerDataMovePoller provides polling facilities until the operation reaches a terminal state.
type RecoveryServicesBackupClientBMSTriggerDataMovePoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *RecoveryServicesBackupClientBMSTriggerDataMovePoller) Done() bool {
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
func (p *RecoveryServicesBackupClientBMSTriggerDataMovePoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final RecoveryServicesBackupClientBMSTriggerDataMoveResponse will be returned.
func (p *RecoveryServicesBackupClientBMSTriggerDataMovePoller) FinalResponse(ctx context.Context) (RecoveryServicesBackupClientBMSTriggerDataMoveResponse, error) {
	respType := RecoveryServicesBackupClientBMSTriggerDataMoveResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return RecoveryServicesBackupClientBMSTriggerDataMoveResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *RecoveryServicesBackupClientBMSTriggerDataMovePoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// RecoveryServicesBackupClientMoveRecoveryPointPoller provides polling facilities until the operation reaches a terminal state.
type RecoveryServicesBackupClientMoveRecoveryPointPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *RecoveryServicesBackupClientMoveRecoveryPointPoller) Done() bool {
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
func (p *RecoveryServicesBackupClientMoveRecoveryPointPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final RecoveryServicesBackupClientMoveRecoveryPointResponse will be returned.
func (p *RecoveryServicesBackupClientMoveRecoveryPointPoller) FinalResponse(ctx context.Context) (RecoveryServicesBackupClientMoveRecoveryPointResponse, error) {
	respType := RecoveryServicesBackupClientMoveRecoveryPointResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return RecoveryServicesBackupClientMoveRecoveryPointResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *RecoveryServicesBackupClientMoveRecoveryPointPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}

// RestoresTriggerPoller provides polling facilities until the operation reaches a terminal state.
type RestoresTriggerPoller struct {
	pt *azcore.Poller
}

// Done returns true if the LRO has reached a terminal state.
func (p *RestoresTriggerPoller) Done() bool {
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
func (p *RestoresTriggerPoller) Poll(ctx context.Context) (*http.Response, error) {
	return p.pt.Poll(ctx)
}

// FinalResponse performs a final GET to the service and returns the final response
// for the polling operation. If there is an error performing the final GET then an error is returned.
// If the final GET succeeded then the final RestoresTriggerResponse will be returned.
func (p *RestoresTriggerPoller) FinalResponse(ctx context.Context) (RestoresTriggerResponse, error) {
	respType := RestoresTriggerResponse{}
	resp, err := p.pt.FinalResponse(ctx, nil)
	if err != nil {
		return RestoresTriggerResponse{}, err
	}
	respType.RawResponse = resp
	return respType, nil
}

// ResumeToken returns a value representing the poller that can be used to resume
// the LRO at a later time. ResumeTokens are unique per service operation.
func (p *RestoresTriggerPoller) ResumeToken() (string, error) {
	return p.pt.ResumeToken()
}
