//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armkusto_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/kusto/armkusto"
)

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsCheckNameAvailability.json
func ExampleManagedPrivateEndpointsClient_CheckNameAvailability() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	_, err = client.CheckNameAvailability(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		armkusto.ManagedPrivateEndpointsCheckNameRequest{
			Name: to.StringPtr("<name>"),
			Type: to.StringPtr("<type>"),
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsList.json
func ExampleManagedPrivateEndpointsClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	_, err = client.List(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsGet.json
func ExampleManagedPrivateEndpointsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		"<managed-private-endpoint-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ManagedPrivateEndpoint.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsCreateOrUpdate.json
func ExampleManagedPrivateEndpointsClient_BeginCreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginCreateOrUpdate(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		"<managed-private-endpoint-name>",
		armkusto.ManagedPrivateEndpoint{
			Properties: &armkusto.ManagedPrivateEndpointProperties{
				GroupID:               to.StringPtr("<group-id>"),
				PrivateLinkResourceID: to.StringPtr("<private-link-resource-id>"),
				RequestMessage:        to.StringPtr("<request-message>"),
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ManagedPrivateEndpoint.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsUpdate.json
func ExampleManagedPrivateEndpointsClient_BeginUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginUpdate(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		"<managed-private-endpoint-name>",
		armkusto.ManagedPrivateEndpoint{
			Properties: &armkusto.ManagedPrivateEndpointProperties{
				GroupID:               to.StringPtr("<group-id>"),
				PrivateLinkResourceID: to.StringPtr("<private-link-resource-id>"),
				RequestMessage:        to.StringPtr("<request-message>"),
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ManagedPrivateEndpoint.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/azure-kusto/resource-manager/Microsoft.Kusto/stable/2021-08-27/examples/KustoManagedPrivateEndpointsDelete.json
func ExampleManagedPrivateEndpointsClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armkusto.NewManagedPrivateEndpointsClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<resource-group-name>",
		"<cluster-name>",
		"<managed-private-endpoint-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}
