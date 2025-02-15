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

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/synapse/armsynapse"
)

// x-ms-original-file: specification/synapse/resource-manager/Microsoft.Synapse/stable/2021-06-01/examples/DataMaskingPolicyCreateOrUpdateMax.json
func ExampleDataMaskingPoliciesClient_CreateOrUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsynapse.NewDataMaskingPoliciesClient("<subscription-id>", cred, nil)
	res, err := client.CreateOrUpdate(ctx,
		"<resource-group-name>",
		"<workspace-name>",
		"<sql-pool-name>",
		armsynapse.DataMaskingPolicy{
			Properties: &armsynapse.DataMaskingPolicyProperties{
				DataMaskingState: armsynapse.DataMaskingStateEnabled.ToPtr(),
				ExemptPrincipals: to.StringPtr("<exempt-principals>"),
			},
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("DataMaskingPolicy.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/synapse/resource-manager/Microsoft.Synapse/stable/2021-06-01/examples/DataMaskingPolicyGet.json
func ExampleDataMaskingPoliciesClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armsynapse.NewDataMaskingPoliciesClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<resource-group-name>",
		"<workspace-name>",
		"<sql-pool-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("DataMaskingPolicy.ID: %s\n", *res.ID)
}
