//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsecurityinsight

import (
	"context"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/runtime"
	"net/http"
	"reflect"
)

// ActionsListByAlertRulePager provides operations for iterating over paged responses.
type ActionsListByAlertRulePager struct {
	client    *ActionsClient
	current   ActionsListByAlertRuleResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, ActionsListByAlertRuleResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *ActionsListByAlertRulePager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *ActionsListByAlertRulePager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.ActionsList.NextLink == nil || len(*p.current.ActionsList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listByAlertRuleHandleError(resp)
		return false
	}
	result, err := p.client.listByAlertRuleHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current ActionsListByAlertRuleResponse page.
func (p *ActionsListByAlertRulePager) PageResponse() ActionsListByAlertRuleResponse {
	return p.current
}

// AlertRuleTemplatesListPager provides operations for iterating over paged responses.
type AlertRuleTemplatesListPager struct {
	client    *AlertRuleTemplatesClient
	current   AlertRuleTemplatesListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, AlertRuleTemplatesListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *AlertRuleTemplatesListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *AlertRuleTemplatesListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.AlertRuleTemplatesList.NextLink == nil || len(*p.current.AlertRuleTemplatesList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current AlertRuleTemplatesListResponse page.
func (p *AlertRuleTemplatesListPager) PageResponse() AlertRuleTemplatesListResponse {
	return p.current
}

// AlertRulesListPager provides operations for iterating over paged responses.
type AlertRulesListPager struct {
	client    *AlertRulesClient
	current   AlertRulesListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, AlertRulesListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *AlertRulesListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *AlertRulesListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.AlertRulesList.NextLink == nil || len(*p.current.AlertRulesList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current AlertRulesListResponse page.
func (p *AlertRulesListPager) PageResponse() AlertRulesListResponse {
	return p.current
}

// BookmarksListPager provides operations for iterating over paged responses.
type BookmarksListPager struct {
	client    *BookmarksClient
	current   BookmarksListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, BookmarksListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *BookmarksListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *BookmarksListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.BookmarkList.NextLink == nil || len(*p.current.BookmarkList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current BookmarksListResponse page.
func (p *BookmarksListPager) PageResponse() BookmarksListResponse {
	return p.current
}

// DataConnectorsListPager provides operations for iterating over paged responses.
type DataConnectorsListPager struct {
	client    *DataConnectorsClient
	current   DataConnectorsListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, DataConnectorsListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *DataConnectorsListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *DataConnectorsListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.DataConnectorList.NextLink == nil || len(*p.current.DataConnectorList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current DataConnectorsListResponse page.
func (p *DataConnectorsListPager) PageResponse() DataConnectorsListResponse {
	return p.current
}

// IncidentCommentsListByIncidentPager provides operations for iterating over paged responses.
type IncidentCommentsListByIncidentPager struct {
	client    *IncidentCommentsClient
	current   IncidentCommentsListByIncidentResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, IncidentCommentsListByIncidentResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *IncidentCommentsListByIncidentPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *IncidentCommentsListByIncidentPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.IncidentCommentList.NextLink == nil || len(*p.current.IncidentCommentList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listByIncidentHandleError(resp)
		return false
	}
	result, err := p.client.listByIncidentHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current IncidentCommentsListByIncidentResponse page.
func (p *IncidentCommentsListByIncidentPager) PageResponse() IncidentCommentsListByIncidentResponse {
	return p.current
}

// IncidentsListPager provides operations for iterating over paged responses.
type IncidentsListPager struct {
	client    *IncidentsClient
	current   IncidentsListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, IncidentsListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *IncidentsListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *IncidentsListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.IncidentList.NextLink == nil || len(*p.current.IncidentList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current IncidentsListResponse page.
func (p *IncidentsListPager) PageResponse() IncidentsListResponse {
	return p.current
}

// OperationsListPager provides operations for iterating over paged responses.
type OperationsListPager struct {
	client    *OperationsClient
	current   OperationsListResponse
	err       error
	requester func(context.Context) (*policy.Request, error)
	advancer  func(context.Context, OperationsListResponse) (*policy.Request, error)
}

// Err returns the last error encountered while paging.
func (p *OperationsListPager) Err() error {
	return p.err
}

// NextPage returns true if the pager advanced to the next page.
// Returns false if there are no more pages or an error occurred.
func (p *OperationsListPager) NextPage(ctx context.Context) bool {
	var req *policy.Request
	var err error
	if !reflect.ValueOf(p.current).IsZero() {
		if p.current.OperationsList.NextLink == nil || len(*p.current.OperationsList.NextLink) == 0 {
			return false
		}
		req, err = p.advancer(ctx, p.current)
	} else {
		req, err = p.requester(ctx)
	}
	if err != nil {
		p.err = err
		return false
	}
	resp, err := p.client.pl.Do(req)
	if err != nil {
		p.err = err
		return false
	}
	if !runtime.HasStatusCode(resp, http.StatusOK) {
		p.err = p.client.listHandleError(resp)
		return false
	}
	result, err := p.client.listHandleResponse(resp)
	if err != nil {
		p.err = err
		return false
	}
	p.current = result
	return true
}

// PageResponse returns the current OperationsListResponse page.
func (p *OperationsListPager) PageResponse() OperationsListResponse {
	return p.current
}
