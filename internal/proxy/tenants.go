package proxy

import (
	"errors"

	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// bucketKeys returns the keys writes to bucket use: its tenant's once the
// tenant is active, the default tenant's otherwise (ADR-038).
func (p *Proxy) bucketKeys(bucket string) (keys.BucketKeys, *s3api.Error) {
	bk, err := p.keys.For(bucket)
	if err != nil {
		return keys.BucketKeys{}, tenantRefusal(err)
	}
	return bk, nil
}

// tenantRefusal is what a client sees for a bucket whose tenant cannot be
// served. The tenant is not named: a client reaches only its own buckets, and
// which tenant holds them is the operator's business.
func tenantRefusal(err error) *s3api.Error {
	switch {
	case errors.Is(err, keys.ErrTenantDestroyed):
		// Refused for good, reads and writes alike. Falling back to the
		// default tenant would store new data in a deleted tenant's bucket
		// under keys nobody intends to destroy.
		return s3api.ErrAccessDenied.WithMessage(
			"The keys of this bucket's tenant were destroyed; the gateway no longer serves it.")
	case errors.Is(err, keys.ErrTenantUnopened):
		// Fail-closed for that tenant only: its buckets get no other keys,
		// and every other tenant goes on being served.
		return s3api.ErrServiceUnavailable.WithMessage(
			"This gateway instance could not open the keys of this bucket's tenant at startup; " +
				"other buckets are unaffected.")
	}
	return s3api.ErrInternal
}
