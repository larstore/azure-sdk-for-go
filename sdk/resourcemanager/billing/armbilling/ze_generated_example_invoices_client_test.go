//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armbilling_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/billing/armbilling"
)

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/BillingAccountInvoicesList.json
func ExampleInvoicesClient_ListByBillingAccount() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	pager := client.ListByBillingAccount("<billing-account-name>",
		"<period-start-date>",
		"<period-end-date>",
		nil)
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("Invoice.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/InvoicesListByBillingProfile.json
func ExampleInvoicesClient_ListByBillingProfile() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	pager := client.ListByBillingProfile("<billing-account-name>",
		"<billing-profile-name>",
		"<period-start-date>",
		"<period-end-date>",
		nil)
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("Invoice.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/CreditNote.json
func ExampleInvoicesClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<billing-account-name>",
		"<invoice-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Invoice.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/InvoiceById.json
func ExampleInvoicesClient_GetByID() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	res, err := client.GetByID(ctx,
		"<invoice-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Invoice.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/ModernInvoiceDownload.json
func ExampleInvoicesClient_BeginDownloadInvoice() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDownloadInvoice(ctx,
		"<billing-account-name>",
		"<invoice-name>",
		"<download-token>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/MultipleModernInvoiceDownload.json
func ExampleInvoicesClient_BeginDownloadMultipleBillingProfileInvoices() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDownloadMultipleBillingProfileInvoices(ctx,
		"<billing-account-name>",
		[]*string{
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01"),
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01"),
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/{billingAccountName}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01")},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/BillingSubscriptionInvoicesList.json
func ExampleInvoicesClient_ListByBillingSubscription() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	pager := client.ListByBillingSubscription("<period-start-date>",
		"<period-end-date>",
		nil)
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("Invoice.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/BillingSubscriptionInvoice.json
func ExampleInvoicesClient_GetBySubscriptionAndInvoiceID() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	res, err := client.GetBySubscriptionAndInvoiceID(ctx,
		"<invoice-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("Invoice.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/BillingSubscriptionInvoiceDownload.json
func ExampleInvoicesClient_BeginDownloadBillingSubscriptionInvoice() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDownloadBillingSubscriptionInvoice(ctx,
		"<invoice-name>",
		"<download-token>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/billing/resource-manager/Microsoft.Billing/stable/2020-05-01/examples/MultipleBillingSubscriptionInvoiceDownload.json
func ExampleInvoicesClient_BeginDownloadMultipleBillingSubscriptionInvoices() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armbilling.NewInvoicesClient("<subscription-id>", cred, nil)
	poller, err := client.BeginDownloadMultipleBillingSubscriptionInvoices(ctx,
		[]*string{
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/default/billingSubscriptions/{subscriptionId}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01"),
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/default/billingSubscriptions/{subscriptionId}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01"),
			to.StringPtr("https://management.azure.com/providers/Microsoft.Billing/billingAccounts/default/billingSubscriptions/{subscriptionId}/invoices/{invoiceName}/download?downloadToken={downloadToken}&useCache=True&api-version=2020-05-01")},
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}
