//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armrecoveryservicessiterecovery_test

import (
	"context"
	"log"

	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/recoveryservices/armrecoveryservicessiterecovery"
)

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_List.json
func ExampleReplicationRecoveryPlansClient_List() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	pager := client.List(nil)
	for pager.NextPage(ctx) {
		if err := pager.Err(); err != nil {
			log.Fatalf("failed to advance page: %v", err)
		}
		for _, v := range pager.PageResponse().Value {
			log.Printf("RecoveryPlan.ID: %s\n", *v.ID)
		}
	}
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_Get.json
func ExampleReplicationRecoveryPlansClient_Get() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	res, err := client.Get(ctx,
		"<recovery-plan-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_Create.json
func ExampleReplicationRecoveryPlansClient_BeginCreate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginCreate(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.CreateRecoveryPlanInput{
			Properties: &armrecoveryservicessiterecovery.CreateRecoveryPlanInputProperties{
				FailoverDeploymentModel: armrecoveryservicessiterecovery.FailoverDeploymentModelResourceManager.ToPtr(),
				Groups: []*armrecoveryservicessiterecovery.RecoveryPlanGroup{
					{
						EndGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
						GroupType:       armrecoveryservicessiterecovery.RecoveryPlanGroupTypeBoot.ToPtr(),
						ReplicationProtectedItems: []*armrecoveryservicessiterecovery.RecoveryPlanProtectedItem{
							{
								ID:               to.StringPtr("<id>"),
								VirtualMachineID: to.StringPtr("<virtual-machine-id>"),
							}},
						StartGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
					}},
				PrimaryFabricID:  to.StringPtr("<primary-fabric-id>"),
				RecoveryFabricID: to.StringPtr("<recovery-fabric-id>"),
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_Delete.json
func ExampleReplicationRecoveryPlansClient_BeginDelete() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginDelete(ctx,
		"<recovery-plan-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	_, err = poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_Update.json
func ExampleReplicationRecoveryPlansClient_BeginUpdate() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginUpdate(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.UpdateRecoveryPlanInput{
			Properties: &armrecoveryservicessiterecovery.UpdateRecoveryPlanInputProperties{
				Groups: []*armrecoveryservicessiterecovery.RecoveryPlanGroup{
					{
						EndGroupActions:           []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
						GroupType:                 armrecoveryservicessiterecovery.RecoveryPlanGroupTypeShutdown.ToPtr(),
						ReplicationProtectedItems: []*armrecoveryservicessiterecovery.RecoveryPlanProtectedItem{},
						StartGroupActions:         []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
					},
					{
						EndGroupActions:           []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
						GroupType:                 armrecoveryservicessiterecovery.RecoveryPlanGroupTypeFailover.ToPtr(),
						ReplicationProtectedItems: []*armrecoveryservicessiterecovery.RecoveryPlanProtectedItem{},
						StartGroupActions:         []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
					},
					{
						EndGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
						GroupType:       armrecoveryservicessiterecovery.RecoveryPlanGroupTypeBoot.ToPtr(),
						ReplicationProtectedItems: []*armrecoveryservicessiterecovery.RecoveryPlanProtectedItem{
							{
								ID:               to.StringPtr("<id>"),
								VirtualMachineID: to.StringPtr("<virtual-machine-id>"),
							}},
						StartGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
					},
					{
						EndGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
						GroupType:       armrecoveryservicessiterecovery.RecoveryPlanGroupTypeBoot.ToPtr(),
						ReplicationProtectedItems: []*armrecoveryservicessiterecovery.RecoveryPlanProtectedItem{
							{
								ID:               to.StringPtr("<id>"),
								VirtualMachineID: to.StringPtr("<virtual-machine-id>"),
							}},
						StartGroupActions: []*armrecoveryservicessiterecovery.RecoveryPlanAction{},
					}},
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_FailoverCancel.json
func ExampleReplicationRecoveryPlansClient_BeginFailoverCancel() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginFailoverCancel(ctx,
		"<recovery-plan-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_FailoverCommit.json
func ExampleReplicationRecoveryPlansClient_BeginFailoverCommit() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginFailoverCommit(ctx,
		"<recovery-plan-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_PlannedFailover.json
func ExampleReplicationRecoveryPlansClient_BeginPlannedFailover() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginPlannedFailover(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.RecoveryPlanPlannedFailoverInput{
			Properties: &armrecoveryservicessiterecovery.RecoveryPlanPlannedFailoverInputProperties{
				FailoverDirection: armrecoveryservicessiterecovery.PossibleOperationsDirectionsPrimaryToRecovery.ToPtr(),
				ProviderSpecificDetails: []armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInputClassification{
					&armrecoveryservicessiterecovery.RecoveryPlanHyperVReplicaAzureFailoverInput{
						RecoveryPlanProviderSpecificFailoverInput: armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInput{
							InstanceType: to.StringPtr("<instance-type>"),
						},
					}},
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_Reprotect.json
func ExampleReplicationRecoveryPlansClient_BeginReprotect() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginReprotect(ctx,
		"<recovery-plan-name>",
		nil)
	if err != nil {
		log.Fatal(err)
	}
	res, err := poller.PollUntilDone(ctx, 30*time.Second)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_TestFailover.json
func ExampleReplicationRecoveryPlansClient_BeginTestFailover() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginTestFailover(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.RecoveryPlanTestFailoverInput{
			Properties: &armrecoveryservicessiterecovery.RecoveryPlanTestFailoverInputProperties{
				FailoverDirection: armrecoveryservicessiterecovery.PossibleOperationsDirectionsPrimaryToRecovery.ToPtr(),
				NetworkID:         to.StringPtr("<network-id>"),
				NetworkType:       to.StringPtr("<network-type>"),
				ProviderSpecificDetails: []armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInputClassification{
					&armrecoveryservicessiterecovery.RecoveryPlanHyperVReplicaAzureFailoverInput{
						RecoveryPlanProviderSpecificFailoverInput: armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInput{
							InstanceType: to.StringPtr("<instance-type>"),
						},
					}},
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_TestFailoverCleanup.json
func ExampleReplicationRecoveryPlansClient_BeginTestFailoverCleanup() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginTestFailoverCleanup(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.RecoveryPlanTestFailoverCleanupInput{
			Properties: &armrecoveryservicessiterecovery.RecoveryPlanTestFailoverCleanupInputProperties{
				Comments: to.StringPtr("<comments>"),
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}

// x-ms-original-file: specification/recoveryservicessiterecovery/resource-manager/Microsoft.RecoveryServices/stable/2021-10-01/examples/ReplicationRecoveryPlans_UnplannedFailover.json
func ExampleReplicationRecoveryPlansClient_BeginUnplannedFailover() {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		log.Fatalf("failed to obtain a credential: %v", err)
	}
	ctx := context.Background()
	client := armrecoveryservicessiterecovery.NewReplicationRecoveryPlansClient("<resource-name>",
		"<resource-group-name>",
		"<subscription-id>", cred, nil)
	poller, err := client.BeginUnplannedFailover(ctx,
		"<recovery-plan-name>",
		armrecoveryservicessiterecovery.RecoveryPlanUnplannedFailoverInput{
			Properties: &armrecoveryservicessiterecovery.RecoveryPlanUnplannedFailoverInputProperties{
				FailoverDirection: armrecoveryservicessiterecovery.PossibleOperationsDirectionsPrimaryToRecovery.ToPtr(),
				ProviderSpecificDetails: []armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInputClassification{
					&armrecoveryservicessiterecovery.RecoveryPlanHyperVReplicaAzureFailoverInput{
						RecoveryPlanProviderSpecificFailoverInput: armrecoveryservicessiterecovery.RecoveryPlanProviderSpecificFailoverInput{
							InstanceType: to.StringPtr("<instance-type>"),
						},
					}},
				SourceSiteOperations: armrecoveryservicessiterecovery.SourceSiteOperationsRequired.ToPtr(),
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
	log.Printf("RecoveryPlan.ID: %s\n", *res.ID)
}
