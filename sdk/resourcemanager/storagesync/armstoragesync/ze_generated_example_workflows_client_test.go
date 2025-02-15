//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armstoragesync_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/storagesync/armstoragesync"
)

// x-ms-original-file: specification/storagesync/resource-manager/Microsoft.StorageSync/stable/2020-09-01/examples/Workflows_ListByStorageSyncService.json
func ExampleWorkflowsClient_ListByStorageSyncService() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armstoragesync.NewWorkflowsClient("<subscription-id>", cred, nil)
	_, err = client.ListByStorageSyncService(ctx,
		"<resource-group-name>",
		"<storage-sync-service-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/storagesync/resource-manager/Microsoft.StorageSync/stable/2020-09-01/examples/Workflows_Get.json
func ExampleWorkflowsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armstoragesync.NewWorkflowsClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<storage-sync-service-name>",
		"<workflow-id>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Workflow.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/storagesync/resource-manager/Microsoft.StorageSync/stable/2020-09-01/examples/Workflows_Abort.json
func ExampleWorkflowsClient_Abort() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armstoragesync.NewWorkflowsClient("<subscription-id>", cred, nil)
	_, err = client.Abort(ctx,
		"<resource-group-name>",
		"<storage-sync-service-name>",
		"<workflow-id>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
}
