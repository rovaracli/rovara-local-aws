package main

import (
	"net/url"
	"strings"
)

// s3OperationName names the S3 operation of a REST request from its method, path shape and sub-resource, for the
// ledger. A port of the fork's S3OperationNames.
func s3OperationName(method, path string, q url.Values, copySource bool) string {
	trimmed := strings.TrimPrefix(path, "/")
	m := strings.ToUpper(method)
	if trimmed == "" {
		return "ListBuckets"
	}
	slash := strings.Index(trimmed, "/")
	bucketOnly := slash < 0 || slash == len(trimmed)-1
	sub := firstSubresource(q)
	has := func(k string) bool { _, ok := q[k]; return ok }
	verbFor := func() string {
		switch m {
		case "GET", "HEAD":
			return "Get"
		case "PUT":
			return "Put"
		case "DELETE":
			return "Delete"
		}
		return m
	}
	if bucketOnly {
		if sub != "" {
			switch sub {
			case "delete":
				return "DeleteObjects"
			case "uploads":
				return "ListMultipartUploads"
			case "versions":
				return "ListObjectVersions"
			}
			return verbFor() + "Bucket" + capitalizeDashed(sub)
		}
		switch m {
		case "PUT":
			return "CreateBucket"
		case "DELETE":
			return "DeleteBucket"
		case "HEAD":
			return "HeadBucket"
		case "GET":
			if has("list-type") {
				return "ListObjectsV2"
			}
			return "ListObjects"
		}
		return m + "Bucket"
	}
	if has("uploads") && m == "POST" {
		return "CreateMultipartUpload"
	}
	if has("uploadId") {
		switch m {
		case "PUT":
			if copySource {
				return "UploadPartCopy"
			}
			return "UploadPart"
		case "POST":
			return "CompleteMultipartUpload"
		case "DELETE":
			return "AbortMultipartUpload"
		case "GET":
			return "ListParts"
		}
		return m + "Upload"
	}
	if sub != "" {
		return verbFor() + "Object" + capitalizeDashed(sub)
	}
	switch m {
	case "PUT":
		if copySource {
			return "CopyObject"
		}
		return "PutObject"
	case "GET":
		return "GetObject"
	case "HEAD":
		return "HeadObject"
	case "DELETE":
		return "DeleteObject"
	case "POST":
		return "PostObject"
	}
	return m + "Object"
}

var s3Subresources = map[string]bool{"acl": true, "cors": true, "lifecycle": true, "policy": true, "tagging": true,
	"versioning": true, "location": true, "notification": true, "encryption": true, "website": true, "logging": true,
	"accelerate": true, "replication": true, "retention": true, "legal-hold": true, "object-lock": true, "attributes": true,
	"uploads": true, "versions": true, "delete": true, "publicAccessBlock": true, "ownershipControls": true, "requestPayment": true}

// firstSubresource picks a sub-resource name; the fork iterated a hash set, so with several the pick is arbitrary there
// too. Sorted here so that the answer is stable.
func firstSubresource(q url.Values) string {
	best := ""
	for k := range q {
		if s3Subresources[k] && (best == "" || k < best) {
			best = k
		}
	}
	return best
}

func capitalizeDashed(s string) string {
	var b strings.Builder
	for _, part := range strings.Split(s, "-") {
		if part != "" {
			b.WriteString(strings.ToUpper(part[:1]))
			b.WriteString(part[1:])
		}
	}
	return b.String()
}
