import java.net.URI;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Consumer;

import software.amazon.awssdk.auth.credentials.AwsBasicCredentials;
import software.amazon.awssdk.auth.credentials.StaticCredentialsProvider;
import software.amazon.awssdk.core.sync.RequestBody;
import software.amazon.awssdk.http.urlconnection.UrlConnectionHttpClient;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.awscore.exception.AwsServiceException;
import software.amazon.awssdk.services.dynamodb.DynamoDbClient;
import software.amazon.awssdk.services.dynamodb.model.*;
import software.amazon.awssdk.services.eventbridge.EventBridgeClient;
import software.amazon.awssdk.services.eventbridge.model.TestEventPatternRequest;
import software.amazon.awssdk.services.s3.S3Client;
import software.amazon.awssdk.services.s3.model.*;
import software.amazon.awssdk.services.secretsmanager.SecretsManagerClient;
import software.amazon.awssdk.services.secretsmanager.model.*;
import software.amazon.awssdk.services.sns.SnsClient;
import software.amazon.awssdk.services.sns.model.*;
import software.amazon.awssdk.services.sqs.SqsClient;
import software.amazon.awssdk.services.sqs.model.*;
import software.amazon.awssdk.services.ssm.SsmClient;
import software.amazon.awssdk.services.ssm.model.*;
import software.amazon.awssdk.services.sts.StsClient;
import software.amazon.awssdk.services.sts.model.GetCallerIdentityRequest;
import software.amazon.awssdk.services.sts.model.GetSessionTokenRequest;

/**
 * AWS SDK for Java v2 compatibility cases for Rovara local AWS. Run with
 * {@code java -cp "$(cat classpath)" compat/java/Compat.java http://127.0.0.1:PORT [validated-endpoint]}.
 * Exit code 0 when every case passes. KMS has no Java client in the offline Maven cache, so it is not covered here.
 */
public class Compat {
    static final String FAKE = "te" + "st";
    static String endpoint;
    static String validated;
    static final String TAG = "jx" + (System.currentTimeMillis() % 100000);
    static int n;

    static String name(String k) { return TAG + "-" + k + (++n); }

    static <B extends software.amazon.awssdk.awscore.client.builder.AwsClientBuilder<B, ?>> B cfg(B b, String ep, String secret) {
        return b.endpointOverride(URI.create(ep)).region(Region.US_EAST_1)
                .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create(FAKE, secret)));
    }

    static S3Client s3() {
        return cfg(S3Client.builder(), endpoint, FAKE).forcePathStyle(true).httpClient(UrlConnectionHttpClient.create()).build();
    }
    static DynamoDbClient ddb() { return cfg(DynamoDbClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static SqsClient sqs() { return cfg(SqsClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static SnsClient sns() { return cfg(SnsClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static StsClient sts() { return cfg(StsClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static SsmClient ssm() { return cfg(SsmClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static SecretsManagerClient sm() { return cfg(SecretsManagerClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }
    static EventBridgeClient events() { return cfg(EventBridgeClient.builder(), endpoint, FAKE).httpClient(UrlConnectionHttpClient.create()).build(); }

    static void check(boolean ok, String msg) { if (!ok) throw new AssertionError(msg); }

    static void errorCode(Runnable call, String... codes) {
        try {
            call.run();
        } catch (AwsServiceException e) {
            String got = e.awsErrorDetails().errorCode();
            for (String c : codes) if (c.equals(got)) return;
            throw new AssertionError("expected one of " + List.of(codes) + ", got " + got + ": " + e.getMessage());
        }
        throw new AssertionError("expected " + List.of(codes) + ", but the call succeeded");
    }

    static final Map<String, Runnable> CASES = new LinkedHashMap<>();

    public static void main(String[] args) {
        endpoint = args[0];
        validated = args.length > 1 ? args[1] : null;

        CASES.put("credentials: wrong key accepted when validation is off", () -> {
            SqsClient odd = SqsClient.builder().endpointOverride(URI.create(endpoint)).region(Region.US_EAST_1)
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIA" + "X".repeat(16), "y".repeat(40))))
                    .httpClient(UrlConnectionHttpClient.create()).build();
            odd.listQueues();
        });
        CASES.put("credentials: signature validation on", () -> {
            if (validated == null) return;
            cfg(SqsClient.builder(), validated, FAKE).httpClient(UrlConnectionHttpClient.create()).build().listQueues();
            errorCode(() -> cfg(SqsClient.builder(), validated, "not-the-secret").httpClient(UrlConnectionHttpClient.create()).build().listQueues(),
                    "InvalidSignatureException", "SignatureDoesNotMatch");
            errorCode(() -> SqsClient.builder().endpointOverride(URI.create(validated)).region(Region.US_EAST_1)
                    .credentialsProvider(StaticCredentialsProvider.create(AwsBasicCredentials.create("AKIA" + "Q".repeat(16), "z".repeat(40))))
                    .httpClient(UrlConnectionHttpClient.create()).build().listQueues(),
                    "UnrecognizedClientException", "InvalidClientTokenId", "InvalidAccessKeyId");
        });
        CASES.put("s3: put, get, tags, list, copy, missing key", () -> {
            S3Client s3 = s3();
            String b = name("b");
            s3.createBucket(CreateBucketRequest.builder().bucket(b).build());
            s3.putObject(PutObjectRequest.builder().bucket(b).key("d/k.txt").contentType("text/plain")
                    .metadata(Map.of("Mixed", "V")).tagging("a=1&b=2").build(), RequestBody.fromString("hello"));
            var got = s3.getObjectAsBytes(GetObjectRequest.builder().bucket(b).key("d/k.txt").build());
            check("V".equals(got.response().metadata().get("mixed")), "metadata");
            check(got.response().tagCount() == 2, "TagCount " + got.response().tagCount());
            check(got.asUtf8String().equals("hello"), "body");
            check(s3.listObjectsV2(ListObjectsV2Request.builder().bucket(b).prefix("d/").build()).contents().size() == 1, "list");
            s3.copyObject(CopyObjectRequest.builder().sourceBucket(b).sourceKey("d/k.txt").destinationBucket(b).destinationKey("c").build());
            errorCode(() -> s3.getObject(GetObjectRequest.builder().bucket(b).key("missing").build()), "NoSuchKey");
        });
        CASES.put("s3: versioning and delete marker", () -> {
            S3Client s3 = s3();
            String b = name("b");
            s3.createBucket(CreateBucketRequest.builder().bucket(b).build());
            s3.putBucketVersioning(PutBucketVersioningRequest.builder().bucket(b)
                    .versioningConfiguration(VersioningConfiguration.builder().status(BucketVersioningStatus.ENABLED).build()).build());
            String v1 = s3.putObject(PutObjectRequest.builder().bucket(b).key("k").build(), RequestBody.fromString("1")).versionId();
            s3.putObject(PutObjectRequest.builder().bucket(b).key("k").build(), RequestBody.fromString("2"));
            String marker = s3.deleteObject(DeleteObjectRequest.builder().bucket(b).key("k").build()).versionId();
            check(marker != null, "marker version id");
            errorCode(() -> s3.getObject(GetObjectRequest.builder().bucket(b).key("k").build()), "NoSuchKey");
            check(s3.getObjectAsBytes(GetObjectRequest.builder().bucket(b).key("k").versionId(v1).build()).asUtf8String().equals("1"), "old version");
        });
        CASES.put("dynamodb: put, query, update, conditional failure, reserved word", () -> {
            DynamoDbClient d = ddb();
            String t = name("t");
            d.createTable(CreateTableRequest.builder().tableName(t).billingMode(BillingMode.PAY_PER_REQUEST)
                    .attributeDefinitions(AttributeDefinition.builder().attributeName("pk").attributeType(ScalarAttributeType.S).build(),
                            AttributeDefinition.builder().attributeName("sk").attributeType(ScalarAttributeType.N).build())
                    .keySchema(KeySchemaElement.builder().attributeName("pk").keyType(KeyType.HASH).build(),
                            KeySchemaElement.builder().attributeName("sk").keyType(KeyType.RANGE).build()).build());
            for (int i = 0; i < 4; i++) {
                d.putItem(PutItemRequest.builder().tableName(t).item(Map.of("pk", AttributeValue.fromS("a"),
                        "sk", AttributeValue.fromN("" + i), "name", AttributeValue.fromS("n" + i))).build());
            }
            var q = d.query(QueryRequest.builder().tableName(t).keyConditionExpression("pk = :p AND sk >= :s")
                    .expressionAttributeValues(Map.of(":p", AttributeValue.fromS("a"), ":s", AttributeValue.fromN("2"))).build());
            check(q.count() == 2, "query count " + q.count());
            var u = d.updateItem(UpdateItemRequest.builder().tableName(t)
                    .key(Map.of("pk", AttributeValue.fromS("a"), "sk", AttributeValue.fromN("0")))
                    .updateExpression("SET c = if_not_exists(c, :z) + :one")
                    .expressionAttributeValues(Map.of(":z", AttributeValue.fromN("0"), ":one", AttributeValue.fromN("1")))
                    .returnValues(ReturnValue.ALL_NEW).build());
            check("1".equals(u.attributes().get("c").n()), "update result");
            errorCode(() -> d.putItem(PutItemRequest.builder().tableName(t).item(Map.of("pk", AttributeValue.fromS("a"), "sk", AttributeValue.fromN("0")))
                    .conditionExpression("attribute_not_exists(pk)").build()), "ConditionalCheckFailedException");
            errorCode(() -> d.getItem(GetItemRequest.builder().tableName(t)
                    .key(Map.of("pk", AttributeValue.fromS("a"), "sk", AttributeValue.fromN("0"))).projectionExpression("name").build()), "ValidationException");
        });
        CASES.put("sqs and sns: visibility, duplicate batch ids, topic to queue with filter", () -> {
            SqsClient q = sqs();
            SnsClient s = sns();
            String url = q.createQueue(CreateQueueRequest.builder().queueName(name("q")).build()).queueUrl();
            String arn = q.getQueueAttributes(GetQueueAttributesRequest.builder().queueUrl(url)
                    .attributeNames(QueueAttributeName.QUEUE_ARN).build()).attributes().get(QueueAttributeName.QUEUE_ARN);
            q.sendMessage(SendMessageRequest.builder().queueUrl(url).messageBody("one").build());
            var m = q.receiveMessage(ReceiveMessageRequest.builder().queueUrl(url).waitTimeSeconds(1).build()).messages();
            check(m.size() == 1 && m.get(0).body().equals("one"), "receive");
            q.deleteMessage(DeleteMessageRequest.builder().queueUrl(url).receiptHandle(m.get(0).receiptHandle()).build());
            errorCode(() -> q.sendMessageBatch(SendMessageBatchRequest.builder().queueUrl(url).entries(
                    SendMessageBatchRequestEntry.builder().id("1").messageBody("a").build(),
                    SendMessageBatchRequestEntry.builder().id("1").messageBody("b").build()).build()),
                    "BatchEntryIdsNotDistinct", "AWS.SimpleQueueService.BatchEntryIdsNotDistinct");
            q.setQueueAttributes(SetQueueAttributesRequest.builder().queueUrl(url).attributes(Map.of(QueueAttributeName.POLICY,
                    "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},"
                            + "\"Action\":\"sqs:SendMessage\",\"Resource\":\"" + arn + "\"}]}")).build());
            String topic = s.createTopic(CreateTopicRequest.builder().name(name("t")).build()).topicArn();
            s.subscribe(SubscribeRequest.builder().topicArn(topic).protocol("sqs").endpoint(arn)
                    .attributes(Map.of("RawMessageDelivery", "true", "FilterPolicy", "{\"kind\":[\"keep\"]}")).build());
            s.publish(PublishRequest.builder().topicArn(topic).message("yes").messageAttributes(Map.of("kind",
                    software.amazon.awssdk.services.sns.model.MessageAttributeValue.builder().dataType("String").stringValue("keep").build())).build());
            s.publish(PublishRequest.builder().topicArn(topic).message("no").messageAttributes(Map.of("kind",
                    software.amazon.awssdk.services.sns.model.MessageAttributeValue.builder().dataType("String").stringValue("drop").build())).build());
            var got = q.receiveMessage(ReceiveMessageRequest.builder().queueUrl(url).waitTimeSeconds(2).maxNumberOfMessages(10).build()).messages();
            check(got.size() == 1 && got.get(0).body().equals("yes"), "filtered delivery: " + got.size());
        });
        CASES.put("sts: caller identity and session token", () -> {
            check(sts().getCallerIdentity(GetCallerIdentityRequest.builder().build()).account().length() == 12, "account");
            check(sts().getSessionToken(GetSessionTokenRequest.builder().durationSeconds(900).build()).credentials().sessionToken() != null, "token");
        });
        CASES.put("secretsmanager and ssm: versions and hierarchy", () -> {
            SecretsManagerClient m = sm();
            String id = name("sec");
            m.createSecret(CreateSecretRequest.builder().name(id).secretString("v1").build());
            m.putSecretValue(PutSecretValueRequest.builder().secretId(id).secretString("v2").build());
            check(m.getSecretValue(GetSecretValueRequest.builder().secretId(id).build()).secretString().equals("v2"), "current");
            check(m.getSecretValue(GetSecretValueRequest.builder().secretId(id).versionStage("AWSPREVIOUS").build()).secretString().equals("v1"), "previous");
            SsmClient p = ssm();
            String root = "/" + name("p");
            p.putParameter(PutParameterRequest.builder().name(root + "/a").value("1").type(ParameterType.STRING).build());
            p.putParameter(PutParameterRequest.builder().name(root + "/b/c").value("2").type(ParameterType.SECURE_STRING).build());
            check(p.getParametersByPath(GetParametersByPathRequest.builder().path(root).recursive(true).withDecryption(true).build()).parameters().size() == 2, "by path");
            errorCode(() -> p.getParametersByPath(GetParametersByPathRequest.builder().path("no-leading-slash").build()), "ValidationException");
        });
        CASES.put("events: TestEventPattern numeric and wildcard operators", () -> {
            EventBridgeClient e = events();
            String event = "{\"id\":\"1\",\"account\":\"000000000000\",\"source\":\"a.b\",\"time\":\"2026-01-01T00:00:00Z\",\"region\":\"us-east-1\","
                    + "\"resources\":[],\"detail-type\":\"t\",\"detail\":{\"price\":15,\"path\":\"/data/x/raw\"}}";
            check(e.testEventPattern(TestEventPatternRequest.builder().eventPattern(
                    "{\"detail\":{\"price\":[{\"numeric\":[\">\",10,\"<=\",20]}],\"path\":[{\"wildcard\":\"/data/*/raw\"}]}}").event(event).build()).result(), "match");
            check(!e.testEventPattern(TestEventPatternRequest.builder().eventPattern(
                    "{\"detail\":{\"price\":[{\"numeric\":[\">\",20]}]}}").event(event).build()).result(), "no match");
        });

        int failed = 0;
        for (Map.Entry<String, Runnable> c : CASES.entrySet()) {
            String status = "pass";
            String msg = "";
            try {
                c.getValue().run();
            } catch (Throwable t) {
                status = "fail";
                msg = t.getClass().getSimpleName() + ": " + t.getMessage();
                failed++;
            }
            System.out.println("[java-sdk-v2] " + status + " " + c.getKey() + (msg.isEmpty() ? "" : " | " + msg));
        }
        System.out.println("[java-sdk-v2] " + (CASES.size() - failed) + "/" + CASES.size() + " passed");
        System.exit(failed == 0 ? 0 : 1);
    }
}
