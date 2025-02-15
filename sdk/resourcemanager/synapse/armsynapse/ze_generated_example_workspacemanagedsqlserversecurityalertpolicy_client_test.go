//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armsynapse_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
)

// x-ms-original-file: specification/synapse/resource-manager/Microsoft.Synapse/stable/2021-06-01/examples/GetWorkspaceManagedSqlServerSecurityAlertPolicy.json
func ExampleWorkspaceManagedSQLServerSecurityAlertPolicyClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsynapse.NewWorkspaceManagedSQLServerSecurityAlertPolicyClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<workspace-name>",
		armsynapse.SecurityAlertPolicyNameAutoGeneratedDefault,
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("ServerSecurityAlertPolicy.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/synapse/resource-manager/Microsoft.Synapse/stable/2021-06-01/examples/WorkspaceManagedSqlServerSecurityAlertWithAllParameters.json
func ExampleWorkspaceManagedSQLServerSecurityAlertPolicyClient_BeginCreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsynapse.NewWorkspaceManagedSQLServerSecurityAlertPolicyClient("<subscription-id>", cred, nil)
	poller, err := client.BeginCreateOrUpdate(ctx,
		"<resource-group-name>",
		"<workspace-name>",
		armsynapse.SecurityAlertPolicyNameAutoGeneratedDefault,
		armsynapse.ServerSecurityAlertPolicy{
			Properties: &armsynapse.ServerSecurityAlertPolicyProperties{
				DisabledAlerts: []*string{
					to.StringPtr("Access_Anomaly"),
					to.StringPtr("Usage_Anomaly")},
				EmailAccountAdmins: to.BoolPtr(true),
				EmailAddresses: []*string{
					to.StringPtr("testSecurityAlert@microsoft.com")},
				RetentionDays:           to.Int32Ptr(5),
				State:                   armsynapse.SecurityAlertPolicyStateEnabled.ToPtr(),
				StorageAccountAccessKey: to.StringPtr("<storage-account-access-key>"),
				StorageEndpoint:         to.StringPtr("<storage-endpoint>"),
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
	log.Printf("ServerSecurityAlertPolicy.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/synapse/resource-manager/Microsoft.Synapse/stable/2021-06-01/examples/ListWorkspaceManagedSqlServerSecurityAlertPolicies.json
func ExampleWorkspaceManagedSQLServerSecurityAlertPolicyClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsynapse.NewWorkspaceManagedSQLServerSecurityAlertPolicyClient("<subscription-id>", cred, nil)
	pager := client.List("<resource-group-name>",
		"<workspace-name>",
		nil)
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("ServerSecurityAlertPolicy.ID: %s\n", *v.ID)
		}
	}
}
