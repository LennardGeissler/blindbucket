package awscreds

import (
	"bufio"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Shared profiles: ~/.aws/credentials and ~/.aws/config, or wherever
// AWS_SHARED_CREDENTIALS_FILE and AWS_CONFIG_FILE point, under the profile
// AWS_PROFILE names or "default".
//
// Three shapes are supported, the ones a machine runs under: static keys, a
// role assumed with a source profile's credentials, and a role assumed with a
// web identity token file. Two are refused with a reason. SSO is a person
// logging in through a browser, which a gateway cannot do, and for a person
// running a command `aws configure export-credentials` turns an SSO session
// into the environment variables the env source reads. credential_process runs
// a command named in a file; a gateway that executed whatever its home
// directory's AWS config named would have handed that file its process
// (ADR-024).

// maxSourceProfileDepth bounds a chain of source_profile references. The SDKs
// allow chains; none needs to be long, and a cycle must end.
const maxSourceProfileDepth = 4

// profiles are the two shared files, parsed.
type profiles struct {
	config      map[string]map[string]string // keyed by profile name, "profile " stripped
	credentials map[string]map[string]string
	configPath  string
	credsPath   string
}

func loadProfiles(opts *Options) (*profiles, error) {
	home := opts.getenv("HOME")
	if home == "" {
		home, _ = os.UserHomeDir()
	}
	p := &profiles{
		configPath: opts.getenv("AWS_CONFIG_FILE"),
		credsPath:  opts.getenv("AWS_SHARED_CREDENTIALS_FILE"),
	}
	if p.configPath == "" {
		p.configPath = filepath.Join(home, ".aws", "config")
	}
	if p.credsPath == "" {
		p.credsPath = filepath.Join(home, ".aws", "credentials")
	}
	var err error
	if p.config, err = readINI(p.configPath, true); err != nil {
		return nil, err
	}
	if p.credentials, err = readINI(p.credsPath, false); err != nil {
		return nil, err
	}
	return p, nil
}

// values merges a profile from both files; the credentials file wins, as it
// does in the SDKs.
func (p *profiles) values(name string) (map[string]string, bool) {
	out := map[string]string{}
	c, inConfig := p.config[name]
	for k, v := range c {
		out[k] = v
	}
	k, inCreds := p.credentials[name]
	for key, v := range k {
		out[key] = v
	}
	return out, inConfig || inCreds
}

func profileName(opts *Options) string {
	if name := opts.getenv("AWS_PROFILE"); name != "" {
		return name
	}
	return "default"
}

// defaultProfilePresent says whether the chain should pick profiles without
// AWS_PROFILE: the default profile exists and says something about
// credentials.
func defaultProfilePresent(opts *Options) bool {
	p, err := loadProfiles(opts)
	if err != nil {
		return false
	}
	values, ok := p.values("default")
	if !ok {
		return false
	}
	for _, key := range []string{"aws_access_key_id", "role_arn", "sso_session", "sso_start_url",
		"credential_process"} {
		if values[key] != "" {
			return true
		}
	}
	return false
}

func profileFetcher(opts *Options) (fetcher, string, error) {
	p, err := loadProfiles(opts)
	if err != nil {
		return nil, "", err
	}
	return p.resolve(opts, profileName(opts), map[string]bool{})
}

func (p *profiles) resolve(opts *Options, name string, seen map[string]bool) (fetcher, string, error) {
	if seen[name] {
		return nil, "", fmt.Errorf("awscreds: profile %q is its own source profile, through a cycle", name)
	}
	if len(seen) >= maxSourceProfileDepth {
		return nil, "", fmt.Errorf("awscreds: profile %q is more than %d source profiles deep",
			name, maxSourceProfileDepth)
	}
	seen[name] = true

	v, ok := p.values(name)
	if !ok {
		return nil, "", fmt.Errorf("awscreds: profile %q is in neither %s nor %s",
			name, p.configPath, p.credsPath)
	}
	where := "profile " + name

	switch {
	case v["role_arn"] != "":
		return p.resolveRole(opts, name, v, seen)
	case v["aws_access_key_id"] != "":
		return staticFetcher(v["aws_access_key_id"], v["aws_secret_access_key"],
			v["aws_session_token"], where)
	case v["sso_session"] != "" || v["sso_start_url"] != "":
		return nil, "", fmt.Errorf("awscreds: %s uses SSO, which is a login for a person and not "+
			"supported here (ADR-024); for a command run by hand, `eval \"$(aws configure "+
			"export-credentials --profile %s --format env)\"` and credential_source: env", where, name)
	case v["credential_process"] != "":
		return nil, "", fmt.Errorf("awscreds: %s uses credential_process, which would run a "+
			"command named in a configuration file and is not supported (ADR-024)", where)
	default:
		return nil, "", fmt.Errorf("awscreds: %s holds no credentials", where)
	}
}

func (p *profiles) resolveRole(opts *Options, name string, v map[string]string,
	seen map[string]bool,
) (fetcher, string, error) {
	where := "profile " + name
	region := stsRegion(opts, v["region"])
	switch {
	case v["mfa_serial"] != "":
		return nil, "", fmt.Errorf("awscreds: %s needs an MFA code for its role, which a "+
			"gateway cannot type", where)
	case v["credential_source"] != "":
		return nil, "", fmt.Errorf("awscreds: %s names credential_source %q; set the gateway's "+
			"own credential_source to that source instead (ADR-024)", where, v["credential_source"])
	case v["web_identity_token_file"] != "":
		return webIdentity{
			tokenFile: v["web_identity_token_file"], roleARN: v["role_arn"],
			sessionName: v["role_session_name"], region: region,
		}.fetcher(opts, where)
	case v["source_profile"] == "":
		return nil, "", fmt.Errorf("awscreds: %s has a role_arn and nothing to assume it with "+
			"(source_profile or web_identity_token_file)", where)
	}

	var (
		source   fetcher
		describe string
		err      error
	)
	if v["source_profile"] == name {
		// A profile may name itself, meaning its own static keys.
		source, describe, err = staticFetcher(v["aws_access_key_id"], v["aws_secret_access_key"],
			v["aws_session_token"], where)
	} else {
		source, describe, err = p.resolve(opts, v["source_profile"], seen)
	}
	if err != nil {
		return nil, "", err
	}
	duration := 0
	if d := v["duration_seconds"]; d != "" {
		if duration, err = strconv.Atoi(d); err != nil || duration <= 0 {
			return nil, "", fmt.Errorf("awscreds: %s: duration_seconds %q is not a number of seconds", where, d)
		}
	}
	return assumeRole(opts, source, v["role_arn"], v["role_session_name"], v["external_id"],
			region, duration),
		fmt.Sprintf("%s, role %s assumed with %s", where, v["role_arn"], describe), nil
}

// readINI parses an AWS shared file. A missing file is an empty one.
//
// The format is the SDKs' INI dialect: [sections], key = value, comments
// starting with # or ;, and indented lines under a key with no value -- the
// nested settings of a service section -- which no credential lives in and
// which are skipped. In the config file a profile's section is
// "[profile name]", except "[default]"; other section kinds (sso-session,
// services) are not profiles and are skipped.
func readINI(path string, isConfig bool) (map[string]map[string]string, error) {
	//nolint:gosec // the path is the operator's own AWS configuration.
	f, err := os.Open(path)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]map[string]string{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("awscreds: %w", err)
	}
	defer func() { _ = f.Close() }()

	out := map[string]map[string]string{}
	var section map[string]string
	nested := false
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		raw := scanner.Text()
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section, nested = nil, false
			name := strings.TrimSpace(line[1 : len(line)-1])
			if isConfig {
				switch {
				case name == "default":
				case strings.HasPrefix(name, "profile "):
					name = strings.TrimSpace(strings.TrimPrefix(name, "profile "))
				default:
					continue // sso-session, services: not a profile
				}
			}
			if out[name] == nil {
				out[name] = map[string]string{}
			}
			section = out[name]
			continue
		}
		if section == nil {
			continue
		}
		indented := raw != "" && (raw[0] == ' ' || raw[0] == '\t')
		if indented && nested {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		value = strings.TrimSpace(value)
		nested = value == ""
		if !nested {
			section[key] = value
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("awscreds: reading %s: %w", path, err)
	}
	return out, nil
}
