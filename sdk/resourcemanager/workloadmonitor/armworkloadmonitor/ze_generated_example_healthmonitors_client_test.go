//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armworkloadmonitor_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/workloadmonitor/armworkloadmonitor"
)

// x-ms-original-file: specification/workloadmonitor/resource-manager/Microsoft.WorkloadMonitor/preview/2020-01-13-preview/examples/MonitorList_GetDefault.json
func ExampleHealthMonitorsClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armworkloadmonitor.NewHealthMonitorsClient(cred, nil)
	pager := client.List("<subscription-id>",
		"<resource-group-name>",
		"<provider-name>",
		"<resource-collection-name>",
		"<resource-name>",
		&armworkloadmonitor.HealthMonitorsListOptions{Filter: nil,
			Expand: nil,
		})
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("HealthMonitor.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/workloadmonitor/resource-manager/Microsoft.WorkloadMonitor/preview/2020-01-13-preview/examples/Monitor_GetDefault.json
func ExampleHealthMonitorsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armworkloadmonitor.NewHealthMonitorsClient(cred, nil)
	res, err := client.Get(ctx,
		"<subscription-id>",
		"<resource-group-name>",
		"<provider-name>",
		"<resource-collection-name>",
		"<resource-name>",
		"<monitor-id>",
		&armworkloadmonitor.HealthMonitorsGetOptions{Expand: nil})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("HealthMonitor.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/workloadmonitor/resource-manager/Microsoft.WorkloadMonitor/preview/2020-01-13-preview/examples/MonitorHistory_GetDefault.json
func ExampleHealthMonitorsClient_ListStateChanges() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armworkloadmonitor.NewHealthMonitorsClient(cred, nil)
	pager := client.ListStateChanges("<subscription-id>",
		"<resource-group-name>",
		"<provider-name>",
		"<resource-collection-name>",
		"<resource-name>",
		"<monitor-id>",
		&armworkloadmonitor.HealthMonitorsListStateChangesOptions{Filter: nil,
			Expand:            nil,
			StartTimestampUTC: to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2020-10-19T19:24:14Z"); return t }()),
			EndTimestampUTC:   to.TimePtr(func() time.Time { t, _ := time.Parse(time.RFC3339Nano, "2020-10-20T01:24:14Z"); return t }()),
		})
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("HealthMonitorStateChange.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/workloadmonitor/resource-manager/Microsoft.WorkloadMonitor/preview/2020-01-13-preview/examples/MonitorStateChange_GetDefault.json
func ExampleHealthMonitorsClient_GetStateChange() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armworkloadmonitor.NewHealthMonitorsClient(cred, nil)
	res, err := client.GetStateChange(ctx,
		"<subscription-id>",
		"<resource-group-name>",
		"<provider-name>",
		"<resource-collection-name>",
		"<resource-name>",
		"<monitor-id>",
		"<timestamp-unix>",
		&armworkloadmonitor.HealthMonitorsGetStateChangeOptions{Expand: nil})
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("HealthMonitorStateChange.ID: %s\n", *res.ID)
}
