//go:build !unix

package main

import "os"

// keepGroup has nothing to keep where files have no Unix group.
func keepGroup(string, os.FileInfo) {}
