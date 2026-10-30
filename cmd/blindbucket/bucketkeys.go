package main

import (
	"context"
	"errors"
	"fmt"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
)

// loadBucketKeyring opens the keyring for a command that reads and writes one
// bucket's objects: the file with the deployment's root key, and then the
// bucket's tenant with the lock keys.tenants names for it, prompting for its
// passphrase if no file holds it. No other tenant's key service is asked.
//
// A destroyed tenant's bucket is refused: nothing in it can be read any more,
// and nothing may be written to it under other keys (ADR-038). So is a tenant
// whose lock does not open here, rather than run against the default
// tenant's keys.
func loadBucketKeyring(
	ctx context.Context, cfg *config.Config, pass *passphraseFlags, bucket string,
) (*keys.Served, keys.BucketKeys, error) {
	f, _, err := openFile(ctx, cfg.Keys.Keyring, cfg.Keys, pass, openTenant(ctx, cfg.Keys))
	if err != nil {
		return nil, keys.BucketKeys{}, err
	}
	name, destroyed := f.Directory().Tenant(bucket)
	if destroyed {
		return nil, keys.BucketKeys{}, fmt.Errorf("s3://%s belongs to tenant %s, which was destroyed; "+
			"its keys are gone and nothing in the bucket can be read", bucket, name)
	}
	if name != keys.DefaultTenant {
		roots := openTenant(ctx, cfg.Keys, name)
		defer roots.wipe()
		if err := f.OpenTenant(name, roots.root); err != nil {
			return nil, keys.BucketKeys{}, fmt.Errorf("s3://%s belongs to tenant %s, whose lock did not "+
				"open: %w", bucket, name, err)
		}
	}
	served := keys.NewServed(f)
	bk, err := served.For(bucket)
	if err != nil {
		return nil, keys.BucketKeys{}, err
	}
	return served, bk, nil
}

// errTenantBucket refuses a tenant's bucket in a command not yet taught that
// its keys and names are the tenant's.
var errTenantBucket = errors.New("does not serve a tenant's buckets yet")

// defaultTenantOnly refuses a bucket that is not the default tenant's.
func defaultTenantOnly(command, bucket string, bk keys.BucketKeys) error {
	if bk.Tenant == keys.DefaultTenant {
		return nil
	}
	return fmt.Errorf("s3://%s belongs to tenant %s, and %s %w", bucket, bk.Tenant, command, errTenantBucket)
}
