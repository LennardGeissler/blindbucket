package awscreds

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
)

// A container credentials endpoint is how ECS hands a task its role and how
// EKS Pod Identity hands a pod its own: an HTTP endpoint on a link-local
// address, named in the environment, answering a JSON document. Pod Identity
// adds an authorization token in a file the kubelet rotates.

// ecsHost is where a relative URI is resolved.
const ecsHost = "http://169.254.170.2"

// maxContainerBody bounds the JSON read from the endpoint.
const maxContainerBody = 1 << 20

type containerAnswer struct {
	AccessKeyID     string    `json:"AccessKeyId"`
	SecretAccessKey string    `json:"SecretAccessKey"`
	Token           string    `json:"Token"`
	Expiration      time.Time `json:"Expiration"`
	Code            string    `json:"code"`
	Message         string    `json:"message"`
}

func containerFetcher(opts *Options) (fetcher, string, error) {
	endpoint, err := containerEndpoint(opts)
	if err != nil {
		return nil, "", err
	}
	tokenFile := opts.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE")
	tokenEnv := opts.getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN")
	describe := "container endpoint " + endpoint

	return func(ctx context.Context) (aws.Credentials, error) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
		if err != nil {
			return aws.Credentials{}, err
		}
		switch {
		case tokenFile != "":
			// Read every time: the Pod Identity token is rotated, and the one
			// read at startup is refused once it has been.
			//nolint:gosec // the path comes from the platform's injected environment.
			token, err := os.ReadFile(tokenFile)
			if err != nil {
				return aws.Credentials{}, fmt.Errorf("reading the container authorization token: %w", err)
			}
			req.Header.Set("Authorization", strings.TrimSpace(string(token)))
		case tokenEnv != "":
			req.Header.Set("Authorization", tokenEnv)
		}
		resp, err := opts.httpClient().Do(req)
		if err != nil {
			return aws.Credentials{}, fmt.Errorf("asking %s: %w", endpoint, err)
		}
		defer func() { _ = resp.Body.Close() }()
		raw, err := io.ReadAll(io.LimitReader(resp.Body, maxContainerBody))
		if err != nil {
			return aws.Credentials{}, err
		}
		var answer containerAnswer
		if err := json.Unmarshal(raw, &answer); err != nil && resp.StatusCode == http.StatusOK {
			return aws.Credentials{}, fmt.Errorf("the container endpoint answered no JSON: %w", err)
		}
		if resp.StatusCode != http.StatusOK {
			if answer.Code != "" {
				return aws.Credentials{}, fmt.Errorf("the container endpoint answered %d: %s: %s",
					resp.StatusCode, answer.Code, answer.Message)
			}
			return aws.Credentials{}, fmt.Errorf("the container endpoint answered %d", resp.StatusCode)
		}
		creds := aws.Credentials{
			AccessKeyID: answer.AccessKeyID, SecretAccessKey: answer.SecretAccessKey,
			SessionToken: answer.Token, Source: "container",
		}
		if !answer.Expiration.IsZero() {
			creds.CanExpire, creds.Expires = true, answer.Expiration
		}
		return creds, nil
	}, describe, nil
}

// containerEndpoint resolves the URI the environment names.
//
// A full URI over plain HTTP is accepted only for the hosts the platforms
// use -- loopback, the ECS address, the EKS Pod Identity agent -- as the SDKs
// accept it. Anything else would be the environment telling the gateway to
// send its authorization token, and fetch its credentials, in clear across a
// network; over HTTPS any host will do.
func containerEndpoint(opts *Options) (string, error) {
	if rel := opts.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI"); rel != "" {
		if !strings.HasPrefix(rel, "/") {
			rel = "/" + rel
		}
		return ecsHost + rel, nil
	}
	full := opts.getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI")
	if full == "" {
		return "", fmt.Errorf("awscreds: the container source needs " +
			"AWS_CONTAINER_CREDENTIALS_RELATIVE_URI or AWS_CONTAINER_CREDENTIALS_FULL_URI, " +
			"which ECS and EKS Pod Identity set")
	}
	u, err := url.Parse(full)
	if err != nil {
		return "", fmt.Errorf("awscreds: AWS_CONTAINER_CREDENTIALS_FULL_URI: %w", err)
	}
	switch u.Scheme {
	case "https":
		return full, nil
	case "http":
		if allowedContainerHost(u.Hostname()) {
			return full, nil
		}
		return "", fmt.Errorf("awscreds: AWS_CONTAINER_CREDENTIALS_FULL_URI names %q over plain "+
			"HTTP; only loopback, 169.254.170.2, 169.254.170.23 and fd00:ec2::23 are accepted "+
			"without TLS", u.Host)
	default:
		return "", fmt.Errorf("awscreds: AWS_CONTAINER_CREDENTIALS_FULL_URI has scheme %q", u.Scheme)
	}
}

func allowedContainerHost(host string) bool {
	switch host {
	case "localhost", "169.254.170.2", "169.254.170.23", "fd00:ec2::23":
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
