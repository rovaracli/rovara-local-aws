# Conformance report: compat-native

Endpoint: `http://127.0.0.1:4581`  
Generated: 2026-11-02T22:51:37-0500

## Process and network

- Peak RSS: 105.5 MiB (first sample 59.6 MiB, 116 samples)
- Network check (no non-loopback connection): **pass**
- Median latency: shape call 2.3 ms, behaviour test 68.1 ms

## Shape conformance (per service)

| service | ops | pass | fail | not_implemented | crash | skipped |
|---|---:|---:|---:|---:|---:|---:|
| iam | 180 | 172 | 6 | 2 | 0 | 0 |
| sts | 11 | 11 | 0 | 0 | 0 | 0 |
| kms | 56 | 38 | 0 | 18 | 0 | 0 |
| s3 | 116 | 89 | 10 | 3 | 0 | 14 |
| dynamodb | 58 | 41 | 10 | 7 | 0 | 0 |
| dynamodbstreams | 4 | 4 | 0 | 0 | 0 | 0 |
| sqs | 23 | 21 | 2 | 0 | 0 | 0 |
| sns | 42 | 39 | 0 | 3 | 0 | 0 |
| secretsmanager | 23 | 23 | 0 | 0 | 0 | 0 |
| ssm | 152 | 35 | 0 | 117 | 0 | 0 |
| kinesis | 45 | 2 | 0 | 8 | 35 | 0 |
| events | 57 | 40 | 0 | 17 | 0 | 0 |
| stepfunctions | 37 | 31 | 0 | 5 | 1 | 0 |
| lambda | 88 | 70 | 0 | 18 | 0 | 0 |
| sagemaker-runtime | 3 | 3 | 0 | 0 | 0 | 0 |
| apigateway | 124 | 106 | 0 | 18 | 0 | 0 |
| **total** | **1019** | **725** | **28** | **216** | **36** | **14** |

Failing operations (unmodelled error code, HTTP 5xx or output not matching the model):

- iam: CreateRole, CreatePolicyVersion, CreateServiceLinkedRole, GetAccountAuthorizationDetails, ListPolicyVersions, ListRoles
- s3: CreateMultipartUpload, CreateSession, CopyObject, PutBucketAcl, PutBucketReplication, PutObject, PutObjectAcl, RestoreObject, GetBucketMetadataConfiguration, GetBucketMetadataTableConfiguration
- dynamodb: PutItem, UpdateItem, BatchGetItem, BatchWriteItem, GetItem, Query, Scan, TransactGetItems, TransactWriteItems, DeleteItem
- sqs: SendMessageBatch, PurgeQueue

Not implemented (unknown-operation style error):

- iam (2): GenerateOrganizationsAccessReport, GetOrganizationsAccessReport
- kms (18): CreateCustomKeyStore, ImportKeyMaterial, EnableKeyRotation, ReplicateKey, RotateKeyOnDemand, UpdateCustomKeyStore, UpdatePrimaryRegion, ConnectCustomKeyStore, Decapsulate, DeriveSharedSecret, DescribeCustomKeyStores, DisconnectCustomKeyStore, Encapsulate, GetKeyLastUsage, GetParametersForImport, ListKeyRotations, DeleteImportedKeyMaterial, DeleteCustomKeyStore
- s3 (3): RenameObject, WriteGetObjectResponse, DeleteObjectTagging
- dynamodb (7): UpdateGlobalTableSettings, UpdateKinesisStreamingDestination, UpdateTableReplicaAutoScaling, DescribeEndpoints, DescribeGlobalTableSettings, DescribeLimits, DescribeTableReplicaAutoScaling
- sns (3): PutDataProtectionPolicy, GetDataProtectionPolicy, ListOriginationNumbers
- ssm (117): CreateActivation, CreateAssociationBatch, CreateCloudConnector, CreateMaintenanceWindow, CreateOpsItem, CreateOpsMetadata, CreatePatchBaseline, CreateResourceDataSync, RegisterDefaultPatchBaseline, RegisterPatchBaselineForPatchGroup, RegisterTargetWithMaintenanceWindow, RegisterTaskWithMaintenanceWindow, AssociateOpsItemRelatedItem, PutComplianceItems, PutInventory, ResumeSession, SendAutomationSignal, SendCommand, StartAccessRequest, StartAssociationsOnce, StartAutomationExecution, StartChangeRequestExecution, StartExecutionPreview, StartSession, UpdateAssociationStatus ...
- kinesis (8): CreateChannel, UpdateAccountSettings, UpdateChannel, DescribeAccountSettings, DescribeChannel, DescribeLimits, ListChannels, DeleteChannel
- events (17): CreateEndpoint, CreatePartnerEventSource, ActivateEventSource, PutPartnerEvents, UpdateEndpoint, DeauthorizeConnection, DescribeEndpoint, DescribeEventSource, DescribePartnerEventSource, ListEndpoints, ListEventSources, ListPartnerEventSourceAccounts, ListPartnerEventSources, ListRuleNamesByTarget, DeletePartnerEventSource, DeleteEndpoint, DeactivateEventSource
- stepfunctions (5): RedriveExecution, UpdateMapRun, DescribeStateMachineForExecution, ListMapRuns, TestState
- lambda (18): CreateCapacityProvider, InvokeAsync, InvokeWithResponseStream, PutFunctionRecursionConfig, PutFunctionScalingConfig, PutResourcePolicy, PutRuntimeManagementConfig, UpdateCapacityProvider, GetCapacityProvider, GetFunctionRecursionConfig, GetFunctionScalingConfig, GetResourcePolicy, GetRuntimeManagementConfig, ListCapacityProviders, ListFunctionUrlConfigs, ListFunctionVersionsByCapacityProvider, DeleteResourcePolicy, DeleteCapacityProvider
- apigateway (18): ImportDocumentationParts, UpdateClientCertificate, UpdateDocumentationPart, UpdateDocumentationVersion, UpdateUsage, FlushStageCache, GetClientCertificate, GetDocumentationPart, GetDocumentationParts, GetDocumentationVersion, GetDocumentationVersions, GetModelTemplate, GetSdk, GetSdkType, DeleteDomainNameAccessAssociation, DeleteDocumentationVersion, DeleteDocumentationPart, DeleteClientCertificate

## Behaviour pack (per service)

| service | tests | pass | fail | not_implemented | needs_function_runner | crash | skipped |
|---|---:|---:|---:|---:|---:|---:|---:|
| s3 | 17 | 16 | 1 | 0 | 0 | 0 | 0 |
| dynamodb | 14 | 14 | 0 | 0 | 0 | 0 | 0 |
| sqs | 13 | 12 | 1 | 0 | 0 | 0 | 0 |
| sns | 8 | 8 | 0 | 0 | 0 | 0 | 0 |
| kms | 7 | 6 | 1 | 0 | 0 | 0 | 0 |
| secretsmanager | 6 | 6 | 0 | 0 | 0 | 0 | 0 |
| ssm | 5 | 5 | 0 | 0 | 0 | 0 | 0 |
| sts | 5 | 4 | 1 | 0 | 0 | 0 | 0 |
| events | 8 | 7 | 1 | 0 | 0 | 0 | 0 |
| stepfunctions | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| sagemaker-runtime | 3 | 3 | 0 | 0 | 0 | 0 | 0 |
| lambda | 6 | 3 | 0 | 0 | 3 | 0 | 0 |
| **total** | **101** | **93** | **5** | **0** | **3** | **0** | **0** |

Tests that did not pass:

| test | status | detail |
|---|---|---|
| s3.s3_presigned_signature_tamper_rejected | fail | URL signed for key a must not read key b: expected 403, got 200 |
| sqs.sqs_queue_attributes_and_missing_queue | fail | expected error ('QueueNameExists',), got QueueAlreadyExists (HTTP 400): An error occurred (QueueAlreadyExists) when calling the CreateQueue  |
| kms.kms_aliases | fail | expected error ('ValidationException',), got InvalidAliasNameException (HTTP 400): An error occurred (InvalidAliasNameException) when callin |
| sts.sts_assume_role_parameter_validation | fail | ParamValidationError: Parameter validation failed:
Invalid value for parameter DurationSeconds, value: 100, valid min value: 900 / raise Par |
| events.events_test_event_pattern_and_put_events_errors | fail | expected error ('ResourceNotFoundException',), but the call succeeded |
| lambda.lambda_invoke_roundtrip | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |
| lambda.lambda_invoke_function_error | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |
| lambda.lambda_sqs_event_source_mapping | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |

Per-operation shape records: `compat-native/shape/<service>/<Operation>.json`.
