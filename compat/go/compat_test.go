package compat

// AWS SDK for Go v2 compatibility cases for Rovara local AWS.
//   COMPAT_ENDPOINT=http://127.0.0.1:PORT go test ./...
// The Go toolchain was not available on the machine that wrote these cases, so the file has not been
// compiled or run yet (compat/run.sh reports "go: not run" in that case). The module versions in go.mod
// are the ones to refresh with `go get -u` on first use.

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	ddbtypes "github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/sqs"
	sqstypes "github.com/aws/aws-sdk-go-v2/service/sqs/types"
	"github.com/aws/aws-sdk-go-v2/service/ssm"
	"github.com/aws/aws-sdk-go-v2/service/sts"
	"github.com/aws/smithy-go"
)

var fake = "te" + "st" // fake credential, assembled at run time

func config(t *testing.T, secret string) aws.Config {
	endpoint := os.Getenv("COMPAT_ENDPOINT")
	if !strings.HasPrefix(endpoint, "http://127.0.0.1") && !strings.HasPrefix(endpoint, "http://localhost") {
		t.Fatal("COMPAT_ENDPOINT must be a loopback URL")
	}
	return aws.Config{
		Region:       "us-east-1",
		Credentials:  credentials.NewStaticCredentialsProvider(fake, secret, ""),
		BaseEndpoint: aws.String(endpoint),
		RetryMaxAttempts: 1,
	}
}

func code(err error) string {
	var api smithy.APIError
	if errors.As(err, &api) {
		return api.ErrorCode()
	}
	return ""
}

func TestWrongKeyAcceptedWhenValidationIsOff(t *testing.T) {
	cfg := config(t, "whatever")
	cfg.Credentials = credentials.NewStaticCredentialsProvider("AKIA"+strings.Repeat("X", 16), strings.Repeat("y", 40), "")
	if _, err := sqs.NewFromConfig(cfg).ListQueues(context.Background(), &sqs.ListQueuesInput{}); err != nil {
		t.Fatal(err)
	}
}

func TestS3PutGetMissing(t *testing.T) {
	ctx := context.Background()
	c := s3.NewFromConfig(config(t, fake), func(o *s3.Options) { o.UsePathStyle = true })
	b := "gx-" + strings.ToLower(time.Now().Format("150405"))
	if _, err := c.CreateBucket(ctx, &s3.CreateBucketInput{Bucket: &b}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.PutObject(ctx, &s3.PutObjectInput{Bucket: &b, Key: aws.String("k"), Body: strings.NewReader("hello")}); err != nil {
		t.Fatal(err)
	}
	out, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: &b, Key: aws.String("k")})
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(out.Body)
	if string(body) != "hello" {
		t.Fatalf("body %q", body)
	}
	if _, err := c.GetObject(ctx, &s3.GetObjectInput{Bucket: &b, Key: aws.String("missing")}); code(err) != "NoSuchKey" {
		t.Fatalf("want NoSuchKey, got %v", err)
	}
}

func TestDynamoDBPutGetConditional(t *testing.T) {
	ctx := context.Background()
	c := dynamodb.NewFromConfig(config(t, fake))
	table := "gx-" + time.Now().Format("150405")
	_, err := c.CreateTable(ctx, &dynamodb.CreateTableInput{
		TableName: &table, BillingMode: ddbtypes.BillingModePayPerRequest,
		AttributeDefinitions: []ddbtypes.AttributeDefinition{{AttributeName: aws.String("pk"), AttributeType: ddbtypes.ScalarAttributeTypeS}},
		KeySchema:            []ddbtypes.KeySchemaElement{{AttributeName: aws.String("pk"), KeyType: ddbtypes.KeyTypeHash}},
	})
	if err != nil {
		t.Fatal(err)
	}
	item := map[string]ddbtypes.AttributeValue{"pk": &ddbtypes.AttributeValueMemberS{Value: "a"}}
	if _, err := c.PutItem(ctx, &dynamodb.PutItemInput{TableName: &table, Item: item}); err != nil {
		t.Fatal(err)
	}
	_, err = c.PutItem(ctx, &dynamodb.PutItemInput{TableName: &table, Item: item, ConditionExpression: aws.String("attribute_not_exists(pk)")})
	if code(err) != "ConditionalCheckFailedException" {
		t.Fatalf("want ConditionalCheckFailedException, got %v", err)
	}
}

func TestSQSSendReceiveDuplicateBatchIds(t *testing.T) {
	ctx := context.Background()
	c := sqs.NewFromConfig(config(t, fake))
	q, err := c.CreateQueue(ctx, &sqs.CreateQueueInput{QueueName: aws.String("gx-" + time.Now().Format("150405"))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.SendMessage(ctx, &sqs.SendMessageInput{QueueUrl: q.QueueUrl, MessageBody: aws.String("one")}); err != nil {
		t.Fatal(err)
	}
	r, err := c.ReceiveMessage(ctx, &sqs.ReceiveMessageInput{QueueUrl: q.QueueUrl, WaitTimeSeconds: 1})
	if err != nil || len(r.Messages) != 1 || *r.Messages[0].Body != "one" {
		t.Fatalf("receive: %v %v", r, err)
	}
	_, err = c.SendMessageBatch(ctx, &sqs.SendMessageBatchInput{QueueUrl: q.QueueUrl, Entries: []sqstypes.SendMessageBatchRequestEntry{
		{Id: aws.String("1"), MessageBody: aws.String("a")}, {Id: aws.String("1"), MessageBody: aws.String("b")}}})
	if c := code(err); c != "BatchEntryIdsNotDistinct" && c != "AWS.SimpleQueueService.BatchEntryIdsNotDistinct" {
		t.Fatalf("want BatchEntryIdsNotDistinct, got %v", err)
	}
}

func TestSTSAndSSM(t *testing.T) {
	ctx := context.Background()
	id, err := sts.NewFromConfig(config(t, fake)).GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil || len(*id.Account) != 12 {
		t.Fatalf("identity: %v %v", id, err)
	}
	p := ssm.NewFromConfig(config(t, fake))
	name := "/gx/" + time.Now().Format("150405")
	if _, err := p.PutParameter(ctx, &ssm.PutParameterInput{Name: &name, Value: aws.String("1"), Type: "String"}); err != nil {
		t.Fatal(err)
	}
	if _, err := p.GetParametersByPath(ctx, &ssm.GetParametersByPathInput{Path: aws.String("no-leading-slash")}); code(err) != "ValidationException" {
		t.Fatalf("want ValidationException, got %v", err)
	}
}
