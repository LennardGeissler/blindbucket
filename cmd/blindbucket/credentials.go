package main

import (
	"fmt"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/awscreds"
	"github.com/LennardGeissler/blindbucket/internal/config"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// awsCredentials resolves a section's credential_source (ADR-024). Keys in
// the configuration come back as nil: the clients take those directly, and a
// nil *awscreds.Credentials must never reach them as a non-nil interface.
func awsCredentials(source, region string) (*awscreds.Credentials, error) {
	if source == "" || source == awscreds.SourceStatic {
		return nil, nil
	}
	return awscreds.New(awscreds.Options{Source: source, Region: region})
}

// upstreamClient builds the client for the configured provider -- the one
// place every command does, so that a credential source is honoured by all of
// them or by none. The credentials are returned too, nil for keys, so that
// serve can name their source and fail at startup when it does not answer.
func upstreamClient(
	cfg *config.Config, observe func(string, time.Duration),
) (*upstream.Client, *awscreds.Credentials, error) {
	u := cfg.Upstream
	creds, err := awsCredentials(u.CredentialSource, u.Region)
	if err != nil {
		return nil, nil, fmt.Errorf("upstream credentials: %w", err)
	}
	ucfg := upstream.Config{
		Endpoint: u.Endpoint, Region: u.Region, PathStyle: u.PathStyle,
		ObserveRequest: observe,
	}
	if creds != nil {
		ucfg.Credentials = creds
	} else {
		ucfg.AccessKeyID, ucfg.SecretAccessKey, ucfg.SessionToken =
			u.AccessKeyID, u.SecretAccessKey, u.SessionToken
	}
	client, err := upstream.New(ucfg)
	if err != nil {
		return nil, nil, err
	}
	return client, creds, nil
}
