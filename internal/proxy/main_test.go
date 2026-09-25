package proxy

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/LennardGeissler/blindbucket/internal/testprovider"
	"github.com/LennardGeissler/blindbucket/internal/testprovider/sweep"
	"github.com/LennardGeissler/blindbucket/internal/upstream"
)

// TestMain sweeps what the run left in the provider's bucket once every test
// has finished: open uploads, objects, and the manifests they orphan. Against a
// real provider those are billed (see internal/testprovider/sweep).
//
// A sweep that fails does not fail the run -- the tests have already said what
// they had to say -- but it is reported, because it means objects were left
// behind on somebody's account.
func TestMain(m *testing.M) {
	code := m.Run()
	if p, err := testprovider.FromEnv(); err == nil && p.Endpoint != "" && !testprovider.Keep() {
		sweepRun(p)
	}
	os.Exit(code)
}

func sweepRun(p testprovider.Provider) {
	client, err := upstream.New(upstream.Config{
		Endpoint: p.Endpoint, Region: p.Region, PathStyle: p.PathStyle,
		AccessKeyID: p.AccessKey, SecretAccessKey: p.SecretKey,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep: %v\n", err)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	result, err := sweep.Run(ctx, client, p.Bucket, testprovider.RunPrefix())
	if err != nil {
		fmt.Fprintf(os.Stderr, "sweep of %s left objects behind: %v\n", testprovider.RunPrefix(), err)
		return
	}
	if testing.Verbose() {
		fmt.Fprintf(os.Stderr, "sweep of %s: %d uploads aborted, %d objects and %d manifests deleted\n",
			testprovider.RunPrefix(), result.UploadsAborted, result.ObjectsDeleted, result.ManifestsDeleted)
	}
}
