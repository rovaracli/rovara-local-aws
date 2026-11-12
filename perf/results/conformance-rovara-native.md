# Conformance report: rovara-native

Endpoint: `http://127.0.0.1:4566`  
Generated: 2026-11-02T21:33:35-0500

## Process and network

- Peak RSS: 127.4 MiB (first sample 59.9 MiB, 154 samples)
- Network check (no non-loopback connection): **pass**
- Median latency: shape call 0.6 ms, behaviour test 11.1 ms

## Shape conformance (per service)

| service | ops | pass | fail | not_implemented | crash | skipped |
|---|---:|---:|---:|---:|---:|---:|
| iam | 180 | 172 | 6 | 2 | 0 | 0 |
| sts | 11 | 11 | 0 | 0 | 0 | 0 |
| kms | 56 | 38 | 0 | 18 | 0 | 0 |
| s3 | 116 | 89 | 10 | 3 | 0 | 14 |
| dynamodb | 58 | 41 | 10 | 7 | 0 | 0 |
| dynamodbstreams | 4 | 4 | 0 | 0 | 0 | 0 |
| sqs | 23 | 22 | 1 | 0 | 0 | 0 |
| sns | 42 | 39 | 0 | 3 | 0 | 0 |
| secretsmanager | 23 | 23 | 0 | 0 | 0 | 0 |
| ssm | 152 | 35 | 0 | 117 | 0 | 0 |
| kinesis | 45 | 2 | 0 | 8 | 35 | 0 |
| events | 57 | 40 | 0 | 17 | 0 | 0 |
| stepfunctions | 37 | 31 | 0 | 5 | 1 | 0 |
| lambda | 88 | 70 | 0 | 18 | 0 | 0 |
| sagemaker-runtime | 3 | 3 | 0 | 0 | 0 | 0 |
| apigateway | 124 | 106 | 0 | 18 | 0 | 0 |
| **total** | **1019** | **726** | **27** | **216** | **36** | **14** |

Failing operations (unmodelled error code, HTTP 5xx or output not matching the model):

- iam: CreateRole, CreatePolicyVersion, CreateServiceLinkedRole, GetAccountAuthorizationDetails, ListPolicyVersions, ListRoles
- s3: CreateMultipartUpload, CreateSession, CopyObject, PutBucketAcl, PutBucketReplication, PutObject, PutObjectAcl, RestoreObject, GetBucketMetadataConfiguration, GetBucketMetadataTableConfiguration
- dynamodb: PutItem, UpdateItem, BatchGetItem, BatchWriteItem, GetItem, Query, Scan, TransactGetItems, TransactWriteItems, DeleteItem
- sqs: SendMessageBatch

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
| s3 | 17 | 14 | 3 | 0 | 0 | 0 | 0 |
| dynamodb | 14 | 11 | 3 | 0 | 0 | 0 | 0 |
| sqs | 13 | 10 | 3 | 0 | 0 | 0 | 0 |
| sns | 8 | 7 | 1 | 0 | 0 | 0 | 0 |
| kms | 7 | 5 | 2 | 0 | 0 | 0 | 0 |
| secretsmanager | 6 | 6 | 0 | 0 | 0 | 0 | 0 |
| ssm | 5 | 3 | 2 | 0 | 0 | 0 | 0 |
| sts | 5 | 4 | 1 | 0 | 0 | 0 | 0 |
| events | 8 | 4 | 4 | 0 | 0 | 0 | 0 |
| stepfunctions | 9 | 9 | 0 | 0 | 0 | 0 | 0 |
| sagemaker-runtime | 3 | 1 | 2 | 0 | 0 | 0 | 0 |
| lambda | 6 | 2 | 1 | 0 | 3 | 0 | 0 |
| **total** | **101** | **76** | **22** | **0** | **3** | **0** | **0** |

Tests that did not pass:

| test | status | detail |
|---|---|---|
| s3.s3_presigned_signature_tamper_rejected | fail | URL signed for key a must not read key b: expected 403, got 200 |
| s3.s3_bucket_name_rules | fail | expected error ('InvalidBucketName',), but the call succeeded |
| s3.s3_metadata_and_tagging_roundtrip | fail | KeyError: 'TagCount' / check_eq(s3.get_object(Bucket=b, Key="k")["TagCount"], 2, "TagCount") |
| dynamodb.ddb_update_expression_semantics | fail | expected error ('ValidationException',), but the call succeeded |
| dynamodb.ddb_reserved_words_need_aliases | fail | expected error ('ValidationException',), but the call succeeded |
| dynamodb.ddb_ttl_configuration | fail | expected error ('ValidationException',), but the call succeeded |
| sqs.sqs_queue_attributes_and_missing_queue | fail | expected error ('QueueNameExists',), got QueueAlreadyExists (HTTP 400): An error occurred (QueueAlreadyExists) when calling the CreateQueue  |
| sqs.sqs_batch_rules | fail | expected error ('BatchEntryIdsNotDistinct', 'AWS.SimpleQueueService.BatchEntryIdsNotDistinct'), but the call succeeded |
| sqs.sqs_message_size_and_purge | fail | expected error ('PurgeQueueInProgress', 'AWS.SimpleQueueService.PurgeQueueInProgress'), but the call succeeded |
| sns.sns_publish_batch | fail | expected error ('BatchEntryIdsNotDistinct',), but the call succeeded |
| kms.kms_pending_deletion_state | fail | expected error ('ValidationException',), but the call succeeded |
| kms.kms_aliases | fail | expected error ('AlreadyExistsException',), but the call succeeded |
| ssm.ssm_get_parameters_by_path | fail | expected error ('ValidationException',), but the call succeeded |
| ssm.ssm_tags_describe_and_limits | fail | expected error ('ValidationException',), but the call succeeded |
| sts.sts_assume_role_parameter_validation | fail | ParamValidationError: Parameter validation failed:
Invalid value for parameter DurationSeconds, value: 100, valid min value: 900 / raise Par |
| events.events_pattern_numeric | fail | matched event ids: expected [0, 1], got [] |
| events.events_pattern_exists_arrays_and_nesting | fail | matched event ids: expected [0], got [] |
| events.events_pattern_suffix_wildcard_case_insensitive | fail | matched event ids: expected [0], got [] |
| events.events_test_event_pattern_and_put_events_errors | fail | match |
| sagemaker-runtime.smr_invoke_async_missing_endpoint | fail | expected error ('ValidationError',), got 404 (HTTP 404): An error occurred (404) when calling the InvokeEndpointAsync operation: <html><body |
| sagemaker-runtime.smr_invoke_stream_missing_endpoint | fail | expected error ('ValidationError',), got 404 (HTTP 404): An error occurred (404) when calling the InvokeEndpointWithResponseStream operation |
| lambda.lambda_invoke_roundtrip | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |
| lambda.lambda_invoke_function_error | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |
| lambda.lambda_sqs_event_source_mapping | needs_function_runner | Invoke reported: b'{"errorMessage":"Failed to start Lambda container: No function runner is available in this build; function code cannot be |
| lambda.lambda_event_source_mapping_validation | fail | expected error ('InvalidParameterValueException',), but the call succeeded |

Per-operation shape records: `rovara-native/shape/<service>/<Operation>.json`.
