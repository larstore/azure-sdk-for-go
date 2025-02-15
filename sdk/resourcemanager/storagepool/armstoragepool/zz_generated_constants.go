//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armstoragepool

const (
	module  = "armstoragepool"
	version = "v0.1.0"
)

// CreatedByType - The type of identity that created the resource.
type CreatedByType string

const (
	CreatedByTypeApplication     CreatedByType = "Application"
	CreatedByTypeKey             CreatedByType = "Key"
	CreatedByTypeManagedIdentity CreatedByType = "ManagedIdentity"
	CreatedByTypeUser            CreatedByType = "User"
)

// PossibleCreatedByTypeValues returns the possible values for the CreatedByType const type.
func PossibleCreatedByTypeValues() []CreatedByType {
	return []CreatedByType{
		CreatedByTypeApplication,
		CreatedByTypeKey,
		CreatedByTypeManagedIdentity,
		CreatedByTypeUser,
	}
}

// ToPtr returns a *CreatedByType pointing to the current value.
func (c CreatedByType) ToPtr() *CreatedByType {
	return &c
}

// DiskPoolTier - SKU of the VM host part of the Disk Pool deployment
type DiskPoolTier string

const (
	DiskPoolTierBasic    DiskPoolTier = "Basic"
	DiskPoolTierPremium  DiskPoolTier = "Premium"
	DiskPoolTierStandard DiskPoolTier = "Standard"
)

// PossibleDiskPoolTierValues returns the possible values for the DiskPoolTier const type.
func PossibleDiskPoolTierValues() []DiskPoolTier {
	return []DiskPoolTier{
		DiskPoolTierBasic,
		DiskPoolTierPremium,
		DiskPoolTierStandard,
	}
}

// ToPtr returns a *DiskPoolTier pointing to the current value.
func (c DiskPoolTier) ToPtr() *DiskPoolTier {
	return &c
}

// IscsiTargetACLMode - ACL mode for iSCSI Target.
type IscsiTargetACLMode string

const (
	IscsiTargetACLModeDynamic IscsiTargetACLMode = "Dynamic"
	IscsiTargetACLModeStatic  IscsiTargetACLMode = "Static"
)

// PossibleIscsiTargetACLModeValues returns the possible values for the IscsiTargetACLMode const type.
func PossibleIscsiTargetACLModeValues() []IscsiTargetACLMode {
	return []IscsiTargetACLMode{
		IscsiTargetACLModeDynamic,
		IscsiTargetACLModeStatic,
	}
}

// ToPtr returns a *IscsiTargetACLMode pointing to the current value.
func (c IscsiTargetACLMode) ToPtr() *IscsiTargetACLMode {
	return &c
}

// OperationalStatus - Operational status of the resource.
type OperationalStatus string

const (
	OperationalStatusHealthy            OperationalStatus = "Healthy"
	OperationalStatusInvalid            OperationalStatus = "Invalid"
	OperationalStatusRunning            OperationalStatus = "Running"
	OperationalStatusStopped            OperationalStatus = "Stopped"
	OperationalStatusStoppedDeallocated OperationalStatus = "Stopped (deallocated)"
	OperationalStatusUnhealthy          OperationalStatus = "Unhealthy"
	OperationalStatusUnknown            OperationalStatus = "Unknown"
	OperationalStatusUpdating           OperationalStatus = "Updating"
)

// PossibleOperationalStatusValues returns the possible values for the OperationalStatus const type.
func PossibleOperationalStatusValues() []OperationalStatus {
	return []OperationalStatus{
		OperationalStatusHealthy,
		OperationalStatusInvalid,
		OperationalStatusRunning,
		OperationalStatusStopped,
		OperationalStatusStoppedDeallocated,
		OperationalStatusUnhealthy,
		OperationalStatusUnknown,
		OperationalStatusUpdating,
	}
}

// ToPtr returns a *OperationalStatus pointing to the current value.
func (c OperationalStatus) ToPtr() *OperationalStatus {
	return &c
}

// ProvisioningStates - Provisioning state of the iSCSI Target.
type ProvisioningStates string

const (
	ProvisioningStatesCanceled  ProvisioningStates = "Canceled"
	ProvisioningStatesCreating  ProvisioningStates = "Creating"
	ProvisioningStatesDeleting  ProvisioningStates = "Deleting"
	ProvisioningStatesFailed    ProvisioningStates = "Failed"
	ProvisioningStatesInvalid   ProvisioningStates = "Invalid"
	ProvisioningStatesPending   ProvisioningStates = "Pending"
	ProvisioningStatesSucceeded ProvisioningStates = "Succeeded"
	ProvisioningStatesUpdating  ProvisioningStates = "Updating"
)

// PossibleProvisioningStatesValues returns the possible values for the ProvisioningStates const type.
func PossibleProvisioningStatesValues() []ProvisioningStates {
	return []ProvisioningStates{
		ProvisioningStatesCanceled,
		ProvisioningStatesCreating,
		ProvisioningStatesDeleting,
		ProvisioningStatesFailed,
		ProvisioningStatesInvalid,
		ProvisioningStatesPending,
		ProvisioningStatesSucceeded,
		ProvisioningStatesUpdating,
	}
}

// ToPtr returns a *ProvisioningStates pointing to the current value.
func (c ProvisioningStates) ToPtr() *ProvisioningStates {
	return &c
}

// ResourceSKURestrictionsReasonCode - The reason for restriction.
type ResourceSKURestrictionsReasonCode string

const (
	ResourceSKURestrictionsReasonCodeQuotaID                     ResourceSKURestrictionsReasonCode = "QuotaId"
	ResourceSKURestrictionsReasonCodeNotAvailableForSubscription ResourceSKURestrictionsReasonCode = "NotAvailableForSubscription"
)

// PossibleResourceSKURestrictionsReasonCodeValues returns the possible values for the ResourceSKURestrictionsReasonCode const type.
func PossibleResourceSKURestrictionsReasonCodeValues() []ResourceSKURestrictionsReasonCode {
	return []ResourceSKURestrictionsReasonCode{
		ResourceSKURestrictionsReasonCodeQuotaID,
		ResourceSKURestrictionsReasonCodeNotAvailableForSubscription,
	}
}

// ToPtr returns a *ResourceSKURestrictionsReasonCode pointing to the current value.
func (c ResourceSKURestrictionsReasonCode) ToPtr() *ResourceSKURestrictionsReasonCode {
	return &c
}

// ResourceSKURestrictionsType - The type of restrictions.
type ResourceSKURestrictionsType string

const (
	ResourceSKURestrictionsTypeLocation ResourceSKURestrictionsType = "Location"
	ResourceSKURestrictionsTypeZone     ResourceSKURestrictionsType = "Zone"
)

// PossibleResourceSKURestrictionsTypeValues returns the possible values for the ResourceSKURestrictionsType const type.
func PossibleResourceSKURestrictionsTypeValues() []ResourceSKURestrictionsType {
	return []ResourceSKURestrictionsType{
		ResourceSKURestrictionsTypeLocation,
		ResourceSKURestrictionsTypeZone,
	}
}

// ToPtr returns a *ResourceSKURestrictionsType pointing to the current value.
func (c ResourceSKURestrictionsType) ToPtr() *ResourceSKURestrictionsType {
	return &c
}
