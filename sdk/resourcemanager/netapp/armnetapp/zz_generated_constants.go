//go:build go1.16
// +build go1.16

// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License. See License.txt in the project root for license information.
// Code generated by Microsoft (R) AutoRest Code Generator.
// Changes may cause incorrect behavior and will be lost if the code is regenerated.

package armnetapp

const (
	module  = "armnetapp"
	version = "v0.1.0"
)

// ActiveDirectoryStatus - Status of the Active Directory
type ActiveDirectoryStatus string

const (
	// ActiveDirectoryStatusCreated - Active Directory created but not in use
	ActiveDirectoryStatusCreated ActiveDirectoryStatus = "Created"
	// ActiveDirectoryStatusDeleted - Active Directory Deleted
	ActiveDirectoryStatusDeleted ActiveDirectoryStatus = "Deleted"
	// ActiveDirectoryStatusError - Error with the Active Directory
	ActiveDirectoryStatusError ActiveDirectoryStatus = "Error"
	// ActiveDirectoryStatusInUse - Active Directory in use by SMB Volume
	ActiveDirectoryStatusInUse ActiveDirectoryStatus = "InUse"
	// ActiveDirectoryStatusUpdating - Active Directory Updating
	ActiveDirectoryStatusUpdating ActiveDirectoryStatus = "Updating"
)

// PossibleActiveDirectoryStatusValues returns the possible values for the ActiveDirectoryStatus const type.
func PossibleActiveDirectoryStatusValues() []ActiveDirectoryStatus {
	return []ActiveDirectoryStatus{
		ActiveDirectoryStatusCreated,
		ActiveDirectoryStatusDeleted,
		ActiveDirectoryStatusError,
		ActiveDirectoryStatusInUse,
		ActiveDirectoryStatusUpdating,
	}
}

// ToPtr returns a *ActiveDirectoryStatus pointing to the current value.
func (c ActiveDirectoryStatus) ToPtr() *ActiveDirectoryStatus {
	return &c
}

// ApplicationType - Application Type
type ApplicationType string

const (
	ApplicationTypeSAPHANA ApplicationType = "SAP-HANA"
)

// PossibleApplicationTypeValues returns the possible values for the ApplicationType const type.
func PossibleApplicationTypeValues() []ApplicationType {
	return []ApplicationType{
		ApplicationTypeSAPHANA,
	}
}

// ToPtr returns a *ApplicationType pointing to the current value.
func (c ApplicationType) ToPtr() *ApplicationType {
	return &c
}

// AvsDataStore - Specifies whether the volume is enabled for Azure VMware Solution (AVS) datastore purpose
type AvsDataStore string

const (
	// AvsDataStoreDisabled - avsDataStore is disabled
	AvsDataStoreDisabled AvsDataStore = "Disabled"
	// AvsDataStoreEnabled - avsDataStore is enabled
	AvsDataStoreEnabled AvsDataStore = "Enabled"
)

// PossibleAvsDataStoreValues returns the possible values for the AvsDataStore const type.
func PossibleAvsDataStoreValues() []AvsDataStore {
	return []AvsDataStore{
		AvsDataStoreDisabled,
		AvsDataStoreEnabled,
	}
}

// ToPtr returns a *AvsDataStore pointing to the current value.
func (c AvsDataStore) ToPtr() *AvsDataStore {
	return &c
}

// BackupType - Type of backup Manual or Scheduled
type BackupType string

const (
	// BackupTypeManual - Manual backup
	BackupTypeManual BackupType = "Manual"
	// BackupTypeScheduled - Scheduled backup
	BackupTypeScheduled BackupType = "Scheduled"
)

// PossibleBackupTypeValues returns the possible values for the BackupType const type.
func PossibleBackupTypeValues() []BackupType {
	return []BackupType{
		BackupTypeManual,
		BackupTypeScheduled,
	}
}

// ToPtr returns a *BackupType pointing to the current value.
func (c BackupType) ToPtr() *BackupType {
	return &c
}

// CheckNameResourceTypes - Resource type used for verification.
type CheckNameResourceTypes string

const (
	CheckNameResourceTypesMicrosoftNetAppNetAppAccounts                              CheckNameResourceTypes = "Microsoft.NetApp/netAppAccounts"
	CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPools                 CheckNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools"
	CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumes          CheckNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools/volumes"
	CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumesSnapshots CheckNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots"
)

// PossibleCheckNameResourceTypesValues returns the possible values for the CheckNameResourceTypes const type.
func PossibleCheckNameResourceTypesValues() []CheckNameResourceTypes {
	return []CheckNameResourceTypes{
		CheckNameResourceTypesMicrosoftNetAppNetAppAccounts,
		CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPools,
		CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumes,
		CheckNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumesSnapshots,
	}
}

// ToPtr returns a *CheckNameResourceTypes pointing to the current value.
func (c CheckNameResourceTypes) ToPtr() *CheckNameResourceTypes {
	return &c
}

// CheckQuotaNameResourceTypes - Resource type used for verification.
type CheckQuotaNameResourceTypes string

const (
	CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccounts                              CheckQuotaNameResourceTypes = "Microsoft.NetApp/netAppAccounts"
	CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPools                 CheckQuotaNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools"
	CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumes          CheckQuotaNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools/volumes"
	CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumesSnapshots CheckQuotaNameResourceTypes = "Microsoft.NetApp/netAppAccounts/capacityPools/volumes/snapshots"
)

// PossibleCheckQuotaNameResourceTypesValues returns the possible values for the CheckQuotaNameResourceTypes const type.
func PossibleCheckQuotaNameResourceTypesValues() []CheckQuotaNameResourceTypes {
	return []CheckQuotaNameResourceTypes{
		CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccounts,
		CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPools,
		CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumes,
		CheckQuotaNameResourceTypesMicrosoftNetAppNetAppAccountsCapacityPoolsVolumesSnapshots,
	}
}

// ToPtr returns a *CheckQuotaNameResourceTypes pointing to the current value.
func (c CheckQuotaNameResourceTypes) ToPtr() *CheckQuotaNameResourceTypes {
	return &c
}

// ChownMode - This parameter specifies who is authorized to change the ownership of a file. restricted - Only root user can change the ownership of the
// file. unrestricted - Non-root users can change ownership of
// files that they own.
type ChownMode string

const (
	ChownModeRestricted   ChownMode = "Restricted"
	ChownModeUnrestricted ChownMode = "Unrestricted"
)

// PossibleChownModeValues returns the possible values for the ChownMode const type.
func PossibleChownModeValues() []ChownMode {
	return []ChownMode{
		ChownModeRestricted,
		ChownModeUnrestricted,
	}
}

// ToPtr returns a *ChownMode pointing to the current value.
func (c ChownMode) ToPtr() *ChownMode {
	return &c
}

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

// EncryptionType - Encryption type of the capacity pool, set encryption type for data at rest for this pool and all volumes in it. This value can only
// be set when creating new pool.
type EncryptionType string

const (
	// EncryptionTypeDouble - EncryptionType Double, volumes will use double encryption at rest
	EncryptionTypeDouble EncryptionType = "Double"
	// EncryptionTypeSingle - EncryptionType Single, volumes will use single encryption at rest
	EncryptionTypeSingle EncryptionType = "Single"
)

// PossibleEncryptionTypeValues returns the possible values for the EncryptionType const type.
func PossibleEncryptionTypeValues() []EncryptionType {
	return []EncryptionType{
		EncryptionTypeDouble,
		EncryptionTypeSingle,
	}
}

// ToPtr returns a *EncryptionType pointing to the current value.
func (c EncryptionType) ToPtr() *EncryptionType {
	return &c
}

// EndpointType - Indicates whether the local volume is the source or destination for the Volume Replication
type EndpointType string

const (
	EndpointTypeDst EndpointType = "dst"
	EndpointTypeSrc EndpointType = "src"
)

// PossibleEndpointTypeValues returns the possible values for the EndpointType const type.
func PossibleEndpointTypeValues() []EndpointType {
	return []EndpointType{
		EndpointTypeDst,
		EndpointTypeSrc,
	}
}

// ToPtr returns a *EndpointType pointing to the current value.
func (c EndpointType) ToPtr() *EndpointType {
	return &c
}

// InAvailabilityReasonType - Invalid indicates the name provided does not match Azure App Service naming requirements. AlreadyExists indicates that the
// name is already in use and is therefore unavailable.
type InAvailabilityReasonType string

const (
	InAvailabilityReasonTypeAlreadyExists InAvailabilityReasonType = "AlreadyExists"
	InAvailabilityReasonTypeInvalid       InAvailabilityReasonType = "Invalid"
)

// PossibleInAvailabilityReasonTypeValues returns the possible values for the InAvailabilityReasonType const type.
func PossibleInAvailabilityReasonTypeValues() []InAvailabilityReasonType {
	return []InAvailabilityReasonType{
		InAvailabilityReasonTypeAlreadyExists,
		InAvailabilityReasonTypeInvalid,
	}
}

// ToPtr returns a *InAvailabilityReasonType pointing to the current value.
func (c InAvailabilityReasonType) ToPtr() *InAvailabilityReasonType {
	return &c
}

type MetricAggregationType string

const (
	MetricAggregationTypeAverage MetricAggregationType = "Average"
)

// PossibleMetricAggregationTypeValues returns the possible values for the MetricAggregationType const type.
func PossibleMetricAggregationTypeValues() []MetricAggregationType {
	return []MetricAggregationType{
		MetricAggregationTypeAverage,
	}
}

// ToPtr returns a *MetricAggregationType pointing to the current value.
func (c MetricAggregationType) ToPtr() *MetricAggregationType {
	return &c
}

// MirrorState - The status of the replication
type MirrorState string

const (
	MirrorStateBroken        MirrorState = "Broken"
	MirrorStateMirrored      MirrorState = "Mirrored"
	MirrorStateUninitialized MirrorState = "Uninitialized"
)

// PossibleMirrorStateValues returns the possible values for the MirrorState const type.
func PossibleMirrorStateValues() []MirrorState {
	return []MirrorState{
		MirrorStateBroken,
		MirrorStateMirrored,
		MirrorStateUninitialized,
	}
}

// ToPtr returns a *MirrorState pointing to the current value.
func (c MirrorState) ToPtr() *MirrorState {
	return &c
}

// NetworkFeatures - Basic network, or Standard features available to the volume.
type NetworkFeatures string

const (
	// NetworkFeaturesBasic - Basic network feature.
	NetworkFeaturesBasic NetworkFeatures = "Basic"
	// NetworkFeaturesStandard - Standard network feature.
	NetworkFeaturesStandard NetworkFeatures = "Standard"
)

// PossibleNetworkFeaturesValues returns the possible values for the NetworkFeatures const type.
func PossibleNetworkFeaturesValues() []NetworkFeatures {
	return []NetworkFeatures{
		NetworkFeaturesBasic,
		NetworkFeaturesStandard,
	}
}

// ToPtr returns a *NetworkFeatures pointing to the current value.
func (c NetworkFeatures) ToPtr() *NetworkFeatures {
	return &c
}

// QosType - The qos type of the pool
type QosType string

const (
	// QosTypeAuto - qos type Auto
	QosTypeAuto QosType = "Auto"
	// QosTypeManual - qos type Manual
	QosTypeManual QosType = "Manual"
)

// PossibleQosTypeValues returns the possible values for the QosType const type.
func PossibleQosTypeValues() []QosType {
	return []QosType{
		QosTypeAuto,
		QosTypeManual,
	}
}

// ToPtr returns a *QosType pointing to the current value.
func (c QosType) ToPtr() *QosType {
	return &c
}

// RelationshipStatus - Status of the mirror relationship
type RelationshipStatus string

const (
	RelationshipStatusIdle         RelationshipStatus = "Idle"
	RelationshipStatusTransferring RelationshipStatus = "Transferring"
)

// PossibleRelationshipStatusValues returns the possible values for the RelationshipStatus const type.
func PossibleRelationshipStatusValues() []RelationshipStatus {
	return []RelationshipStatus{
		RelationshipStatusIdle,
		RelationshipStatusTransferring,
	}
}

// ToPtr returns a *RelationshipStatus pointing to the current value.
func (c RelationshipStatus) ToPtr() *RelationshipStatus {
	return &c
}

// ReplicationSchedule - Schedule
type ReplicationSchedule string

const (
	ReplicationSchedule10Minutely ReplicationSchedule = "_10minutely"
	ReplicationScheduleDaily      ReplicationSchedule = "daily"
	ReplicationScheduleHourly     ReplicationSchedule = "hourly"
)

// PossibleReplicationScheduleValues returns the possible values for the ReplicationSchedule const type.
func PossibleReplicationScheduleValues() []ReplicationSchedule {
	return []ReplicationSchedule{
		ReplicationSchedule10Minutely,
		ReplicationScheduleDaily,
		ReplicationScheduleHourly,
	}
}

// ToPtr returns a *ReplicationSchedule pointing to the current value.
func (c ReplicationSchedule) ToPtr() *ReplicationSchedule {
	return &c
}

// SecurityStyle - The security style of volume, default unix, defaults to ntfs for dual protocol or CIFS protocol
type SecurityStyle string

const (
	SecurityStyleNtfs SecurityStyle = "ntfs"
	SecurityStyleUnix SecurityStyle = "unix"
)

// PossibleSecurityStyleValues returns the possible values for the SecurityStyle const type.
func PossibleSecurityStyleValues() []SecurityStyle {
	return []SecurityStyle{
		SecurityStyleNtfs,
		SecurityStyleUnix,
	}
}

// ToPtr returns a *SecurityStyle pointing to the current value.
func (c SecurityStyle) ToPtr() *SecurityStyle {
	return &c
}

// ServiceLevel - The service level of the file system
type ServiceLevel string

const (
	// ServiceLevelPremium - Premium service level
	ServiceLevelPremium ServiceLevel = "Premium"
	// ServiceLevelStandard - Standard service level
	ServiceLevelStandard ServiceLevel = "Standard"
	// ServiceLevelStandardZRS - Zone redundant storage service level
	ServiceLevelStandardZRS ServiceLevel = "StandardZRS"
	// ServiceLevelUltra - Ultra service level
	ServiceLevelUltra ServiceLevel = "Ultra"
)

// PossibleServiceLevelValues returns the possible values for the ServiceLevel const type.
func PossibleServiceLevelValues() []ServiceLevel {
	return []ServiceLevel{
		ServiceLevelPremium,
		ServiceLevelStandard,
		ServiceLevelStandardZRS,
		ServiceLevelUltra,
	}
}

// ToPtr returns a *ServiceLevel pointing to the current value.
func (c ServiceLevel) ToPtr() *ServiceLevel {
	return &c
}

// VolumeStorageToNetworkProximity - Provides storage to network proximity information for the volume.
type VolumeStorageToNetworkProximity string

const (
	// VolumeStorageToNetworkProximityDefault - Basic storage to network connectivity.
	VolumeStorageToNetworkProximityDefault VolumeStorageToNetworkProximity = "Default"
	// VolumeStorageToNetworkProximityT1 - Standard T1 storage to network connectivity.
	VolumeStorageToNetworkProximityT1 VolumeStorageToNetworkProximity = "T1"
	// VolumeStorageToNetworkProximityT2 - Standard T2 storage to network connectivity.
	VolumeStorageToNetworkProximityT2 VolumeStorageToNetworkProximity = "T2"
)

// PossibleVolumeStorageToNetworkProximityValues returns the possible values for the VolumeStorageToNetworkProximity const type.
func PossibleVolumeStorageToNetworkProximityValues() []VolumeStorageToNetworkProximity {
	return []VolumeStorageToNetworkProximity{
		VolumeStorageToNetworkProximityDefault,
		VolumeStorageToNetworkProximityT1,
		VolumeStorageToNetworkProximityT2,
	}
}

// ToPtr returns a *VolumeStorageToNetworkProximity pointing to the current value.
func (c VolumeStorageToNetworkProximity) ToPtr() *VolumeStorageToNetworkProximity {
	return &c
}
