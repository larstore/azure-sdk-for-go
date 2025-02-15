package documentdb

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
//
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

import (
	"context"
	"github.com/Azure/go-autorest/autorest"
	"github.com/Azure/go-autorest/autorest/azure"
	"github.com/Azure/go-autorest/autorest/validation"
	"github.com/Azure/go-autorest/tracing"
	"net/http"
)

// DatabaseAccountRegionClient is the client for the DatabaseAccountRegion methods of the Documentdb service.
type DatabaseAccountRegionClient struct {
	BaseClient
}

// NewDatabaseAccountRegionClient creates an instance of the DatabaseAccountRegionClient client.
func NewDatabaseAccountRegionClient(subscriptionID string) DatabaseAccountRegionClient {
	return NewDatabaseAccountRegionClientWithBaseURI(DefaultBaseURI, subscriptionID)
}

// NewDatabaseAccountRegionClientWithBaseURI creates an instance of the DatabaseAccountRegionClient client using a
// custom endpoint.  Use this when interacting with an Azure cloud that uses a non-standard base URI (sovereign clouds,
// Azure stack).
func NewDatabaseAccountRegionClientWithBaseURI(baseURI string, subscriptionID string) DatabaseAccountRegionClient {
	return DatabaseAccountRegionClient{NewWithBaseURI(baseURI, subscriptionID)}
}

// ListMetrics retrieves the metrics determined by the given filter for the given database account and region.
// Parameters:
// resourceGroupName - the name of the resource group. The name is case insensitive.
// accountName - cosmos DB database account name.
// region - cosmos DB region, with spaces between words and each word capitalized.
// filter - an OData filter expression that describes a subset of metrics to return. The parameters that can be
// filtered are name.value (name of the metric, can have an or of multiple names), startTime, endTime, and
// timeGrain. The supported operator is eq.
func (client DatabaseAccountRegionClient) ListMetrics(ctx context.Context, resourceGroupName string, accountName string, region string, filter string) (result MetricListResult, err error) {
	if tracing.IsEnabled() {
		ctx = tracing.StartSpan(ctx, fqdn+"/DatabaseAccountRegionClient.ListMetrics")
		defer func() {
			sc := -1
			if result.Response.Response != nil {
				sc = result.Response.Response.StatusCode
			}
			tracing.EndSpan(ctx, sc, err)
		}()
	}
	if err := validation.Validate([]validation.Validation{
		{TargetValue: client.SubscriptionID,
			Constraints: []validation.Constraint{{Target: "client.SubscriptionID", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: resourceGroupName,
			Constraints: []validation.Constraint{{Target: "resourceGroupName", Name: validation.MaxLength, Rule: 90, Chain: nil},
				{Target: "resourceGroupName", Name: validation.MinLength, Rule: 1, Chain: nil}}},
		{TargetValue: accountName,
			Constraints: []validation.Constraint{{Target: "accountName", Name: validation.MaxLength, Rule: 50, Chain: nil},
				{Target: "accountName", Name: validation.MinLength, Rule: 3, Chain: nil},
				{Target: "accountName", Name: validation.Pattern, Rule: `^[a-z0-9]+(-[a-z0-9]+)*`, Chain: nil}}}}); err != nil {
		return result, validation.NewError("documentdb.DatabaseAccountRegionClient", "ListMetrics", err.Error())
	}

	req, err := client.ListMetricsPreparer(ctx, resourceGroupName, accountName, region, filter)
	if err != nil {
		err = autorest.NewErrorWithError(err, "documentdb.DatabaseAccountRegionClient", "ListMetrics", nil, "Failure preparing request")
		return
	}

	resp, err := client.ListMetricsSender(req)
	if err != nil {
		result.Response = autorest.Response{Response: resp}
		err = autorest.NewErrorWithError(err, "documentdb.DatabaseAccountRegionClient", "ListMetrics", resp, "Failure sending request")
		return
	}

	result, err = client.ListMetricsResponder(resp)
	if err != nil {
		err = autorest.NewErrorWithError(err, "documentdb.DatabaseAccountRegionClient", "ListMetrics", resp, "Failure responding to request")
		return
	}

	return
}

// ListMetricsPreparer prepares the ListMetrics request.
func (client DatabaseAccountRegionClient) ListMetricsPreparer(ctx context.Context, resourceGroupName string, accountName string, region string, filter string) (*http.Request, error) {
	pathParameters := map[string]interface{}{
		"accountName":       autorest.Encode("path", accountName),
		"region":            autorest.Encode("path", region),
		"resourceGroupName": autorest.Encode("path", resourceGroupName),
		"subscriptionId":    autorest.Encode("path", client.SubscriptionID),
	}

	const APIVersion = "2021-03-01-preview"
	queryParameters := map[string]interface{}{
		"$filter":     autorest.Encode("query", filter),
		"api-version": APIVersion,
	}

	preparer := autorest.CreatePreparer(
		autorest.AsGet(),
		autorest.WithBaseURL(client.BaseURI),
		autorest.WithPathParameters("/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DocumentDB/databaseAccounts/{accountName}/region/{region}/metrics", pathParameters),
		autorest.WithQueryParameters(queryParameters))
	return preparer.Prepare((&http.Request{}).WithContext(ctx))
}

// ListMetricsSender sends the ListMetrics request. The method will close the
// http.Response Body if it receives an error.
func (client DatabaseAccountRegionClient) ListMetricsSender(req *http.Request) (*http.Response, error) {
	return client.Send(req, azure.DoRetryWithRegistration(client.Client))
}

// ListMetricsResponder handles the response to the ListMetrics request. The method always
// closes the http.Response Body.
func (client DatabaseAccountRegionClient) ListMetricsResponder(resp *http.Response) (result MetricListResult, err error) {
	err = autorest.Respond(
		resp,
		azure.WithErrorUnlessStatusCode(http.StatusOK),
		autorest.ByUnmarshallingJSON(&result),
		autorest.ByClosing())
	result.Response = autorest.Response{Response: resp}
	return
}
