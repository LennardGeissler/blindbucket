package main

import (
	"context"
	"fmt"
	"log/slog"
	"slices"

	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/crypto/keys"
	"github.com/LennardGeissler/blindbucket/internal/crypto/names"
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

// tenantKIDs returns the key ids of a tenant of served, the default tenant's
// included.
func tenantKIDs(served *keys.Served, tenant string) []string {
	if tenant == keys.DefaultTenant {
		return served.Default().KIDs()
	}
	for _, t := range served.Tenants() {
		if t.Name == tenant {
			return t.KIDs
		}
	}
	return nil
}

// bucketNames builds the encrypter the gateway maps a bucket's object names
// with, or nil while names.encrypt is off: the default tenant's name key, or
// once the bucket's tenant is active, the tenant's (ADR-038).
func bucketNames(
	cfg *config.Config, served *keys.Served, bk keys.BucketKeys, log *slog.Logger,
) (*names.Encrypter, error) {
	if !cfg.Names.Encrypt {
		return nil, nil
	}
	if bk.NameTenant == keys.DefaultTenant {
		return openNameEncrypter(cfg, served.Default(), log)
	}
	if bk.Name == nil {
		return nil, fmt.Errorf("tenant %s has no name key", bk.NameTenant)
	}
	secret := bk.Name.Secret()
	defer clear(secret)
	return names.New(secret)
}

// tenantOfKID names the tenant of served that holds kid.
func tenantOfKID(served *keys.Served, kid string) (string, bool) {
	if slices.Contains(served.Default().KIDs(), kid) {
		return keys.DefaultTenant, true
	}
	for _, t := range served.Tenants() {
		if slices.Contains(t.KIDs, kid) {
			return t.Name, true
		}
	}
	return "", false
}
