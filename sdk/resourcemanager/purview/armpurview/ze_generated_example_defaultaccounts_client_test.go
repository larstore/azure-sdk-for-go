//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armpurview_test

import (
	"context"
	"log"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/purview/armpurview"
)

// x-ms-original-file: specification/purview/resource-manager/Microsoft.Purview/stable/2021-07-01/examples/DefaultAccounts_Get.json
func ExampleDefaultAccountsClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armpurview.NewDefaultAccountsClient(cred, nil)
	_, err = client.Get(ctx,
		"<scope-tenant-id>",
		armpurview.ScopeTypeTenant,
		&armpurview.DefaultAccountsGetOptions{Scope: to.StringPtr("<scope>")})
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/purview/resource-manager/Microsoft.Purview/stable/2021-07-01/examples/DefaultAccounts_Set.json
func ExampleDefaultAccountsClient_Set() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armpurview.NewDefaultAccountsClient(cred, nil)
	_, err = client.Set(ctx,
		armpurview.DefaultAccountPayload{
			AccountName:       to.StringPtr("<account-name>"),
			ResourceGroupName: to.StringPtr("<resource-group-name>"),
			Scope:             to.StringPtr("<scope>"),
			ScopeTenantID:     to.StringPtr("<scope-tenant-id>"),
			ScopeType:         armpurview.ScopeTypeTenant.ToPtr(),
			SubscriptionID:    to.StringPtr("<subscription-id>"),
		},
		nil)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/purview/resource-manager/Microsoft.Purview/stable/2021-07-01/examples/DefaultAccounts_Remove.json
func ExampleDefaultAccountsClient_Remove() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armpurview.NewDefaultAccountsClient(cred, nil)
	_, err = client.Remove(ctx,
		"<scope-tenant-id>",
		armpurview.ScopeTypeTenant,
		&armpurview.DefaultAccountsRemoveOptions{Scope: to.StringPtr("<scope>")})
	if err != nil {
		log.Fatal(err)
	}
}
