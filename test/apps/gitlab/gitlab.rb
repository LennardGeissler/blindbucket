# GitLab's configuration in the scenario, for either GitLab:
# SCENARIO_MODE is plain or names, and picks the gateway, the port and the
# buckets. Mounted into the container and read through GITLAB_OMNIBUS_CONFIG.
mode = ENV.fetch('SCENARIO_MODE')
port = { 'plain' => 8181, 'names' => 8182 }.fetch(mode)

external_url "http://localhost:#{port}"
gitlab_rails['initial_root_password'] = 'Kq7v-Tz3m-Wx9p-Ld2r'  # GitLab refuses anything resembling a word

# Object storage in the consolidated form: one connection, a bucket per kind
# of object. It is what turns on Workhorse's own S3 client, which uploads with
# the connection's credentials rather than through presigned URLs.
gitlab_rails['object_store']['enabled'] = true
gitlab_rails['object_store']['proxy_download'] = false
gitlab_rails['object_store']['allowed_download_modes'] = %w[direct proxy]
gitlab_rails['object_store']['connection'] = {
  'provider' => 'AWS',
  'region' => 'us-east-1',
  'endpoint' => "http://gateway-#{mode}:9000",
  'path_style' => true,
  'aws_access_key_id' => "GITLABSCENARIO#{mode.upcase}",
  'aws_secret_access_key' => "gitlab-scenario-secret-#{mode}",
}
%w[artifacts lfs uploads packages].each do |kind|
  gitlab_rails['object_store']['objects'][kind]['bucket'] = "gl-#{kind}-#{mode}"
end
%w[external_diffs dependency_proxy terraform_state ci_secure_files pages ci_catalog_bundles].each do |kind|
  gitlab_rails['object_store']['objects'][kind]['enabled'] = false
end

# As little as GitLab runs in: Docker Desktop's default is 4 GB, and GitLab
# wants all of it. Nothing here touches object storage.
puma['worker_processes'] = 0
sidekiq['concurrency'] = 5
prometheus_monitoring['enable'] = false
gitlab_kas['enable'] = false
registry['enable'] = false
gitlab_pages['enable'] = false
gitlab_rails['usage_ping_enabled'] = false
letsencrypt['enable'] = false
