package proxy

import (
	"github.com/LennardGeissler/blindbucket/internal/s3api"
)

// What the race tests in package proxy_test need from inside the gateway:
// the coordination points of hooks.go, and a way to hold a request at one.
// Everything else they do through the gateway's S3 interface, like the rest
// of the integration suite.
const (
	HookUpHead      = hookUpHead
	HookUpManifest  = hookUpManifest
	HookUpComplete  = hookUpComplete
	HookUpCleanup   = hookUpCleanup
	HookDelHead     = hookDelHead
	HookDelRemove   = hookDelRemove
	HookDelManifest = hookDelManifest
)

// SetHook installs the coordination hook on p, or removes it with nil.
func SetHook(p *Proxy, hook func(point string, req s3api.Request)) { p.hook = hook }
