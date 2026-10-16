package proxytest

import "encoding/xml"

// The S3 documents the tests send and read, declared here rather than taken
// from the gateway: a test that decodes the gateway's answer with the
// gateway's own types cannot catch a mistake in them.

// CompleteRequest is the body of CompleteMultipartUpload.
type CompleteRequest struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompletedPart is one part of a CompleteRequest.
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// CopyObjectResult is the body of a CopyObject response.
type CopyObjectResult struct {
	XMLName      xml.Name `xml:"CopyObjectResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// CopyPartResult is the body of an UploadPartCopy response.
type CopyPartResult struct {
	XMLName      xml.Name `xml:"CopyPartResult"`
	ETag         string   `xml:"ETag"`
	LastModified string   `xml:"LastModified"`
}

// ListPartsResult is the body of a ListParts response.
type ListPartsResult struct {
	XMLName      xml.Name     `xml:"ListPartsResult"`
	Bucket       string       `xml:"Bucket"`
	Key          string       `xml:"Key"`
	UploadID     string       `xml:"UploadId"`
	StorageClass string       `xml:"StorageClass,omitempty"`
	IsTruncated  bool         `xml:"IsTruncated"`
	Parts        []PartListed `xml:"Part"`
}

// PartListed is one part of a ListPartsResult.
type PartListed struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
	Size       int64  `xml:"Size"`
}
