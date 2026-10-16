package doctor

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// CertExpiryWarning is how long before its expiry a certificate is warned
// about: long enough to renew it by hand.
const CertExpiryWarning = 14 * 24 * time.Hour

// TLS checks that the listener's certificate and key load and pair, and how
// long the certificate has left.
func TLS(certFile, keyFile string, now time.Time) Check {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return Fail(NameTLS, err.Error(), fmt.Sprintf("server.tls.cert_file (%s) and server.tls.key_file (%s) "+
			"must be a readable PEM certificate and its private key", certFile, keyFile))
	}
	leaf := pair.Leaf
	if leaf == nil {
		if leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
			return Fail(NameTLS, err.Error(), "server.tls.cert_file does not hold a certificate Go can parse")
		}
	}
	until := leaf.NotAfter.UTC().Format(time.DateOnly)
	switch left := leaf.NotAfter.Sub(now); {
	case now.Before(leaf.NotBefore):
		return Fail(NameTLS, "the certificate is not valid before "+leaf.NotBefore.UTC().Format(time.DateOnly),
			"check this host's clock, or the certificate's validity period")
	case left <= 0:
		return Fail(NameTLS, "the certificate expired on "+until,
			"renew the certificate in server.tls.cert_file; clients refuse an expired one")
	case left < CertExpiryWarning:
		return Warn(NameTLS, "the certificate expires on "+until,
			"renew the certificate in server.tls.cert_file before it expires")
	}
	return Ok(NameTLS, "certificate and key pair; valid until "+until)
}

// Writable checks that serve can create or append to path, which setting
// names. It writes a temporary file beside path and removes it, and opens an
// existing file for appending without writing to it.
func Writable(name, setting, path string) Check {
	dir := filepath.Dir(path)
	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return Fail(name, fmt.Sprintf("%s is not a directory", dir),
			fmt.Sprintf("create %s, or point %s somewhere that exists", dir, setting))
	}
	probe, err := os.CreateTemp(dir, ".blindbucket-doctor-*")
	if err != nil {
		return Fail(name, err.Error(),
			fmt.Sprintf("the user serve runs as must be able to create files in %s", dir))
	}
	_ = probe.Close()
	_ = os.Remove(probe.Name())

	switch info, err := os.Stat(path); {
	case errors.Is(err, os.ErrNotExist):
		return Ok(name, fmt.Sprintf("%s does not exist yet; serve can create it", path))
	case err != nil:
		return Fail(name, err.Error(), fmt.Sprintf("check %s", setting))
	case !info.Mode().IsRegular():
		return Fail(name, fmt.Sprintf("%s is not a regular file", path),
			fmt.Sprintf("point %s at a file, not a directory or device", setting))
	}
	//nolint:gosec // the path is the operator's own configuration.
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		return Fail(name, err.Error(),
			fmt.Sprintf("the user serve runs as must be able to write %s", path))
	}
	_ = f.Close()
	return Ok(name, fmt.Sprintf("%s exists and is writable", path))
}
