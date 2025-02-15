//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armmaintenance_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/maintenance/armmaintenance"
)

// x-ms-original-file: specification/maintenance/resource-manager/Microsoft.Maintenance/preview/2021-09-01-preview/examples/Updates_ListParent.json
func ExampleUpdatesClient_ListParent() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmaintenance.NewUpdatesClient("<subscription-id>", cred, nil)
	_, err = client.ListParent(ctx,
		"<resource-group-name>",
		"<provider-name>",
		"<resource-parent-type>",
		"<resource-parent-name>",
		"<resource-type>",
		"<resource-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/maintenance/resource-manager/Microsoft.Maintenance/preview/2021-09-01-preview/examples/Updates_List.json
func ExampleUpdatesClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armmaintenance.NewUpdatesClient("<subscription-id>", cred, nil)
	_, err = client.List(ctx,
		"<resource-group-name>",
		"<provider-name>",
		"<resource-type>",
		"<resource-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}
