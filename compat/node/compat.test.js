'use strict';
// AWS SDK for JavaScript v3 compatibility cases. Run: node --test compat/node/ with
// COMPAT_ENDPOINT=http://127.0.0.1:PORT and NODE_PATH pointing at a node_modules that holds @aws-sdk/client-*.
// Optional COMPAT_VALIDATED_ENDPOINT for the signature-validation case.
const test = require('node:test');
const assert = require('node:assert/strict');

const endpoint = process.env.COMPAT_ENDPOINT;
assert.ok(endpoint && /^http:\/\/(127\.0\.0\.1|localhost)/.test(endpoint), 'COMPAT_ENDPOINT must be a loopback URL');
const validated = process.env.COMPAT_VALIDATED_ENDPOINT;
const FAKE = 'te' + 'st'; // fake credential, assembled at run time
const base = (ep, secret) => ({ endpoint: ep || endpoint, region: 'us-east-1',
  credentials: { accessKeyId: FAKE, secretAccessKey: secret || FAKE }, maxAttempts: 1 });
const tag = 'nx' + (Date.now() % 100000);
let n = 0;
const name = (k) => `${tag}-${k}${++n}`;
const streamText = async (body) => Buffer.from(await body.transformToByteArray()).toString('utf8');
const rejectsWith = async (p, ...codes) => {
  try { await p; } catch (e) { assert.ok(codes.includes(e.name) || codes.includes(e.Code) || codes.includes(e.__type), `got ${e.name}: ${e.message}`); return e; }
  assert.fail(`expected one of ${codes}`);
};

test('credentials: no Authorization header is served; a wrong key is accepted when validation is off', async () => {
  const r = await fetch(endpoint + '/', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' },
    body: 'Action=ListQueues&Version=2012-11-05' });
  assert.equal(r.status, 200);
  const { SQSClient, ListQueuesCommand } = require('@aws-sdk/client-sqs');
  const odd = new SQSClient({ ...base(), credentials: { accessKeyId: 'AKIA' + 'X'.repeat(16), secretAccessKey: 'y'.repeat(40) } });
  await odd.send(new ListQueuesCommand({}));
});

test('credentials: signature validation on refuses an unknown key and a wrong secret', { skip: !validated }, async () => {
  const { SQSClient, ListQueuesCommand } = require('@aws-sdk/client-sqs');
  await new SQSClient(base(validated)).send(new ListQueuesCommand({}));
  await rejectsWith(new SQSClient(base(validated, 'not-the-secret')).send(new ListQueuesCommand({})),
    'InvalidSignatureException', 'SignatureDoesNotMatch');
  await rejectsWith(new SQSClient({ ...base(validated), credentials: { accessKeyId: 'AKIA' + 'Q'.repeat(16), secretAccessKey: 'z'.repeat(40) } })
    .send(new ListQueuesCommand({})), 'UnrecognizedClientException', 'InvalidClientTokenId', 'InvalidAccessKeyId');
});

test('s3: put, get, list, presigned get, missing key', async () => {
  const { S3Client, CreateBucketCommand, PutObjectCommand, GetObjectCommand, ListObjectsV2Command, DeleteObjectsCommand } = require('@aws-sdk/client-s3');
  const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');
  const s3 = new S3Client({ ...base(), forcePathStyle: true });
  const b = name('b');
  await s3.send(new CreateBucketCommand({ Bucket: b }));
  await s3.send(new PutObjectCommand({ Bucket: b, Key: 'd/k.txt', Body: 'hello', ContentType: 'text/plain', Metadata: { Mixed: 'V' }, Tagging: 'a=1&b=2' }));
  const got = await s3.send(new GetObjectCommand({ Bucket: b, Key: 'd/k.txt' }));
  assert.equal(await streamText(got.Body), 'hello');
  assert.deepEqual(got.Metadata, { mixed: 'V' });
  assert.equal(got.TagCount, 2);
  const list = await s3.send(new ListObjectsV2Command({ Bucket: b, Prefix: 'd/' }));
  assert.deepEqual(list.Contents.map((o) => o.Key), ['d/k.txt']);
  const url = await getSignedUrl(s3, new GetObjectCommand({ Bucket: b, Key: 'd/k.txt' }), { expiresIn: 60 });
  const r = await fetch(url);
  assert.equal(r.status, 200);
  assert.equal(await r.text(), 'hello');
  await rejectsWith(s3.send(new GetObjectCommand({ Bucket: b, Key: 'missing' })), 'NoSuchKey');
  await s3.send(new DeleteObjectsCommand({ Bucket: b, Delete: { Objects: [{ Key: 'd/k.txt' }] } }));
});

test('dynamodb: put, query, update expression, conditional failure, reserved word', async () => {
  const { DynamoDBClient, CreateTableCommand } = require('@aws-sdk/client-dynamodb');
  const { DynamoDBDocumentClient, PutCommand, QueryCommand, UpdateCommand, GetCommand } = require('@aws-sdk/lib-dynamodb');
  const raw = new DynamoDBClient(base());
  const ddb = DynamoDBDocumentClient.from(raw);
  const t = name('t');
  await raw.send(new CreateTableCommand({ TableName: t, BillingMode: 'PAY_PER_REQUEST',
    AttributeDefinitions: [{ AttributeName: 'pk', AttributeType: 'S' }, { AttributeName: 'sk', AttributeType: 'N' }],
    KeySchema: [{ AttributeName: 'pk', KeyType: 'HASH' }, { AttributeName: 'sk', KeyType: 'RANGE' }] }));
  for (let i = 0; i < 4; i++) await ddb.send(new PutCommand({ TableName: t, Item: { pk: 'a', sk: i, name: 'n' + i } }));
  const q = await ddb.send(new QueryCommand({ TableName: t, KeyConditionExpression: 'pk = :p AND sk >= :s',
    ExpressionAttributeValues: { ':p': 'a', ':s': 2 } }));
  assert.deepEqual(q.Items.map((i) => i.sk), [2, 3]);
  const u = await ddb.send(new UpdateCommand({ TableName: t, Key: { pk: 'a', sk: 0 }, UpdateExpression: 'SET c = if_not_exists(c, :z) + :one',
    ExpressionAttributeValues: { ':z': 0, ':one': 1 }, ReturnValues: 'ALL_NEW' }));
  assert.equal(u.Attributes.c, 1);
  await rejectsWith(ddb.send(new PutCommand({ TableName: t, Item: { pk: 'a', sk: 0 }, ConditionExpression: 'attribute_not_exists(pk)' })),
    'ConditionalCheckFailedException');
  await rejectsWith(ddb.send(new GetCommand({ TableName: t, Key: { pk: 'a', sk: 0 }, ProjectionExpression: 'name' })), 'ValidationException');
});

test('sqs and sns: visibility, batch, topic with filter policy to a queue', async () => {
  const { SQSClient, CreateQueueCommand, GetQueueAttributesCommand, SetQueueAttributesCommand, SendMessageCommand,
    ReceiveMessageCommand, DeleteMessageCommand, SendMessageBatchCommand } = require('@aws-sdk/client-sqs');
  const { SNSClient, CreateTopicCommand, SubscribeCommand, PublishCommand } = require('@aws-sdk/client-sns');
  const sqs = new SQSClient(base());
  const sns = new SNSClient(base());
  const { QueueUrl } = await sqs.send(new CreateQueueCommand({ QueueName: name('q') }));
  const { Attributes } = await sqs.send(new GetQueueAttributesCommand({ QueueUrl, AttributeNames: ['QueueArn'] }));
  await sqs.send(new SendMessageCommand({ QueueUrl, MessageBody: 'one' }));
  const m = (await sqs.send(new ReceiveMessageCommand({ QueueUrl, WaitTimeSeconds: 1 }))).Messages[0];
  assert.equal(m.Body, 'one');
  await sqs.send(new DeleteMessageCommand({ QueueUrl, ReceiptHandle: m.ReceiptHandle }));
  await rejectsWith(sqs.send(new SendMessageBatchCommand({ QueueUrl, Entries: [{ Id: '1', MessageBody: 'a' }, { Id: '1', MessageBody: 'b' }] })),
    'BatchEntryIdsNotDistinct', 'AWS.SimpleQueueService.BatchEntryIdsNotDistinct');
  await sqs.send(new SetQueueAttributesCommand({ QueueUrl, Attributes: { Policy: JSON.stringify({ Version: '2012-10-17', Statement: [
    { Effect: 'Allow', Principal: { Service: 'sns.amazonaws.com' }, Action: 'sqs:SendMessage', Resource: Attributes.QueueArn }] }) } }));
  const { TopicArn } = await sns.send(new CreateTopicCommand({ Name: name('t') }));
  await sns.send(new SubscribeCommand({ TopicArn, Protocol: 'sqs', Endpoint: Attributes.QueueArn,
    Attributes: { RawMessageDelivery: 'true', FilterPolicy: JSON.stringify({ kind: ['keep'] }) } }));
  await sns.send(new PublishCommand({ TopicArn, Message: 'yes', MessageAttributes: { kind: { DataType: 'String', StringValue: 'keep' } } }));
  await sns.send(new PublishCommand({ TopicArn, Message: 'no', MessageAttributes: { kind: { DataType: 'String', StringValue: 'drop' } } }));
  const got = (await sqs.send(new ReceiveMessageCommand({ QueueUrl, WaitTimeSeconds: 2, MaxNumberOfMessages: 10 }))).Messages || [];
  assert.deepEqual(got.map((x) => x.Body), ['yes']);
});

test('sts: caller identity and session token', async () => {
  const { STSClient, GetCallerIdentityCommand, GetSessionTokenCommand } = require('@aws-sdk/client-sts');
  const sts = new STSClient(base());
  assert.equal((await sts.send(new GetCallerIdentityCommand({}))).Account.length, 12);
  assert.ok((await sts.send(new GetSessionTokenCommand({ DurationSeconds: 900 }))).Credentials.SessionToken);
});

test('secretsmanager and ssm: versions, hierarchy', async () => {
  const { SecretsManagerClient, CreateSecretCommand, PutSecretValueCommand, GetSecretValueCommand } = require('@aws-sdk/client-secrets-manager');
  const { SSMClient, PutParameterCommand, GetParametersByPathCommand, GetParameterCommand } = require('@aws-sdk/client-ssm');
  const sm = new SecretsManagerClient(base());
  const id = name('sec');
  await sm.send(new CreateSecretCommand({ Name: id, SecretString: 'v1' }));
  await sm.send(new PutSecretValueCommand({ SecretId: id, SecretString: 'v2' }));
  assert.equal((await sm.send(new GetSecretValueCommand({ SecretId: id }))).SecretString, 'v2');
  assert.equal((await sm.send(new GetSecretValueCommand({ SecretId: id, VersionStage: 'AWSPREVIOUS' }))).SecretString, 'v1');
  const ssm = new SSMClient(base());
  const root = '/' + name('p');
  await ssm.send(new PutParameterCommand({ Name: root + '/a', Value: '1', Type: 'String' }));
  await ssm.send(new PutParameterCommand({ Name: root + '/b/c', Value: '2', Type: 'SecureString' }));
  const r = await ssm.send(new GetParametersByPathCommand({ Path: root, Recursive: true, WithDecryption: true }));
  assert.deepEqual(r.Parameters.map((p) => p.Name.slice(root.length)).sort(), ['/a', '/b/c']);
  assert.equal((await ssm.send(new GetParameterCommand({ Name: root + '/a' }))).Parameter.Version, 1);
  await rejectsWith(ssm.send(new GetParametersByPathCommand({ Path: 'no-leading-slash' })), 'ValidationException');
});

test('kms: encrypt and decrypt with context and alias', async () => {
  const { KMSClient, CreateKeyCommand, CreateAliasCommand, EncryptCommand, DecryptCommand } = require('@aws-sdk/client-kms');
  const kms = new KMSClient(base());
  const k = (await kms.send(new CreateKeyCommand({}))).KeyMetadata.KeyId;
  const alias = 'alias/' + name('a');
  await kms.send(new CreateAliasCommand({ AliasName: alias, TargetKeyId: k }));
  const ct = (await kms.send(new EncryptCommand({ KeyId: alias, Plaintext: Buffer.from('secret'), EncryptionContext: { a: 'b' } }))).CiphertextBlob;
  const pt = (await kms.send(new DecryptCommand({ CiphertextBlob: ct, EncryptionContext: { a: 'b' } }))).Plaintext;
  assert.equal(Buffer.from(pt).toString(), 'secret');
  await rejectsWith(kms.send(new DecryptCommand({ CiphertextBlob: ct, EncryptionContext: { a: 'other' } })), 'InvalidCiphertextException');
});
