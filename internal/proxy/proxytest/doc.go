// Package proxytest runs a gateway against a real S3-compatible provider, for
// the tests of internal/proxy and of the commands that work on what it
// stores: rotate, migrate, scrub and gc.
//
// A real provider, because the interesting failures are the ones a fake would
// paper over: what a provider stores, what it returns, and what happens when
// the stored bytes are changed behind the gateway's back. The Harness talks to
// the gateway as an S3 client would, signing with the AWS SDK, and to the
// provider directly, to do what a hostile one would.
//
//	docker compose up -d
//	BLINDBUCKET_TEST_S3_ENDPOINT=http://localhost:9002 go test ./internal/proxy/...
//
// Any other provider works the same way; internal/testprovider lists the
// variables that describe it. Without one, every test that needs it skips.
//
// It is imported only by tests and is in no binary.
package proxytest
