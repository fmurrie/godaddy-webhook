#!/usr/bin/env bash

set -Eeuo pipefail

k8s_version="1.36.0"
# Pinned upstream setup-envtest revision for controller-runtime v0.24.
controller_runtime_version="d3eaef3ab45410342c30528d1eaab982137c4d5a"
goos="$(go env GOOS)"
goarch="$(go env GOARCH)"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)"
output_root="${OUTPUT_ROOT:-"$repo_root/_out"}"
if [[ "$output_root" != /* ]]; then
  output_root="$repo_root/$output_root"
fi
tool_root="$output_root/tools"
asset_root="$output_root/kubebuilder"
setup_envtest="$tool_root/setup-envtest"

mkdir -p "$tool_root" "$asset_root/bin"

if [[ ! -x "$setup_envtest" ]]; then
  GOBIN="$tool_root" go install \
    "sigs.k8s.io/controller-runtime/tools/setup-envtest@${controller_runtime_version}"
fi

assets_path="$($setup_envtest use "$k8s_version" --bin-dir "$asset_root" -p path)"
for binary_name in etcd kubectl kube-apiserver; do
  [[ -x "$assets_path/$binary_name" ]] || {
    printf 'ERROR: envtest asset is missing: %s\n' "$assets_path/$binary_name" >&2
    exit 1
  }
  ln -sfn "$assets_path/$binary_name" "$asset_root/bin/$binary_name"
done

printf 'Installed Kubernetes %s envtest assets for %s/%s at %s\n' \
  "$k8s_version" "$goos" "$goarch" "$asset_root/bin"
