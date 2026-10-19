package proxy

import (
	"errors"
	"net/http"

	"github.com/LennardGeissler/blindbucket/internal/auth"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// translateAuth maps a verification failure onto the S3 error a client expects.
//
// The distinctions are preserved rather than flattened into one 403: an SDK
// retries a skewed clock after resyncing, prompts for credentials on
// InvalidAccessKeyId, and gives up on SignatureDoesNotMatch. Collapsing them
// would turn a fixable misconfiguration into a mystery.
func translateAuth(err error) *s3api.Error {
	switch {
	case errors.Is(err, auth.ErrMissingAuth):
		return s3api.ErrAccessDenied.WithMessage("the request is not signed")
	case errors.Is(err, auth.ErrMalformedAuth):
		return s3api.ErrAuthHeaderMalformed.WithMessage("%v", err)
	case errors.Is(err, auth.ErrUnknownAccessKey):
		return s3api.ErrInvalidAccessKeyID
	case errors.Is(err, auth.ErrSignatureMismatch), errors.Is(err, auth.ErrChunkSignature):
		return s3api.ErrSignatureDoesNotMatch
	case errors.Is(err, auth.ErrRequestTimeTooSkewed):
		return s3api.ErrRequestTimeTooSkewed
	case errors.Is(err, auth.ErrBucketNotAllowed):
		// Deliberately the same answer a nonexistent bucket would get: a caller
		// must not be able to map which buckets exist by comparing errors.
		return s3api.ErrAccessDenied
	case errors.Is(err, auth.ErrUnsupportedPayload), errors.Is(err, auth.ErrUnsupportedChecksum):
		return s3api.ErrNotImplemented.WithMessage("%v", err)
	default:
		return s3api.ErrAccessDenied
	}
}

// translateBody maps a body-verification failure onto an S3 error.
func translateBody(err error) *s3api.Error {
	switch {
	case errors.Is(err, auth.ErrChecksumMismatch):
		return s3api.ErrBadDigest.WithMessage("%v", err)
	case errors.Is(err, auth.ErrChunkSignature):
		return s3api.ErrSignatureDoesNotMatch
	case errors.Is(err, auth.ErrMalformedChunkedBody):
		return s3api.ErrIncompleteBody.WithMessage("%v", err)
	case errors.Is(err, auth.ErrUnsupportedChecksum):
		return s3api.ErrNotImplemented.WithMessage("%v", err)
	case errors.Is(err, auth.ErrMissingContentLength):
		return s3api.ErrMissingContentLength
	default:
		return s3api.ErrIncompleteBody.WithMessage("the request body ended before it was complete")
	}
}

// translateUpstream turns a provider error into the S3 error a client expects.
//
// Provider errors are forwarded rather than flattened: a client that asked for a
// missing key must see NoSuchKey, not a gateway fault it might retry forever.
func translateUpstream(err error) *s3api.Error {
	apiErr, ok := upstream.AsAPIError(err)
	if !ok {
		return s3api.ErrInternal.WithMessage("upstream request failed")
	}
	// Two conditional writes to one key raced, and the provider asks the loser
	// to retry. Only this 409 is passed on as it is: the others (a bucket that
	// is not empty, an upload in progress) mean something the gateway answers
	// itself.
	if apiErr.StatusCode == http.StatusConflict && apiErr.Code == "ConditionalRequestConflict" {
		return &s3api.Error{Code: apiErr.Code, Message: apiErr.Message,
			HTTPStatus: http.StatusConflict}
	}
	switch apiErr.StatusCode {
	case http.StatusNotFound:
		if apiErr.Code == "NoSuchBucket" {
			return s3api.ErrNoSuchBucket
		}
		return s3api.ErrNoSuchKey
	case http.StatusForbidden:
		return s3api.ErrAccessDenied
	case http.StatusPreconditionFailed:
		return &s3api.Error{Code: "PreconditionFailed", Message: apiErr.Message,
			HTTPStatus: http.StatusPreconditionFailed}
	case http.StatusRequestedRangeNotSatisfiable:
		return s3api.ErrInvalidRange
	default:
		return &s3api.Error{
			Code:       "InternalError",
			Message:    "The upstream storage provider returned " + apiErr.Code + ".",
			HTTPStatus: http.StatusBadGateway,
		}
	}
}
