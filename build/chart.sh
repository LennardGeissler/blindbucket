#!/usr/bin/env bash
# Keeps the Helm chart's version honest, and publishes it.
#
#   build/chart.sh check <base>   fail if the chart changed since <base> but its
#                                 version did not; print "new" or "same"
#   build/chart.sh publish        package the chart and push it to ghcr.io
#   build/chart.sh metadata       push Artifact Hub's repository metadata next
#                                 to it (deploy/helm/artifacthub-repo.yml)
#
# A published chart version must never change its contents: whoever pinned
# 0.2.0 has to keep getting what 0.2.0 was. The chart has a version of its own
# in Chart.yaml, and appVersion -- the gateway release it deploys -- is part of
# its contents, so a release that moves appVersion is a chart change and needs a
# new chart version as well.
#
# Whether a version is new is decided from git, not by asking the registry:
# ghcr.io answers a chart that does not exist yet with the same 403 it gives a
# private one, so "not published" and "not allowed to look" cannot be told
# apart from outside.
set -euo pipefail

chart=deploy/helm/blindbucket
registry=oci://ghcr.io/lennardgeissler/charts
# Where the metadata goes: the chart's own repository, under the tag Artifact
# Hub reads. Overridable only so that a local registry can stand in for a test.
metadata_ref=${CHART_METADATA_REF:-ghcr.io/lennardgeissler/charts/blindbucket:artifacthub.io}

version_at() { # <rev> -- the chart version at a revision, empty if absent there
	git show "$1:$chart/Chart.yaml" 2>/dev/null | awk '$1 == "version:" { print $2; exit }'
}

current=$(awk '$1 == "version:" { print $2; exit }' "$chart/Chart.yaml")

case ${1:-} in
check)
	base=${2:?usage: build/chart.sh check <base>}
	if git diff --quiet "$base" -- "$chart"; then
		echo same
		exit 0
	fi
	previous=$(version_at "$base")
	if [ "$previous" = "$current" ]; then
		echo "::error file=$chart/Chart.yaml::the chart changed but its version is still $current;" \
			"a published version must not change, so give it a new one" >&2
		git diff --stat "$base" -- "$chart" >&2
		exit 1
	fi
	echo new
	;;
publish)
	work=$(mktemp -d)
	trap 'rm -rf "$work"' EXIT
	helm package "$chart" --destination "$work"
	helm push "$work/blindbucket-$current.tgz" "$registry"
	;;
metadata)
	# The media types are Artifact Hub's, and the file is pushed from its own
	# directory so that the layer's title is its bare name.
	cd deploy/helm
	oras push "$metadata_ref" \
		--config /dev/null:application/vnd.cncf.artifacthub.config.v1+yaml \
		artifacthub-repo.yml:application/vnd.cncf.artifacthub.repository-metadata.layer.v1.yaml
	;;
*)
	echo "usage: build/chart.sh check <base> | publish | metadata" >&2
	exit 2
	;;
esac
