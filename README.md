# GoDaddy DNS-01 webhook for cert-manager

This maintained fork provides a cert-manager external DNS webhook for the
GoDaddy API. It tracks cert-manager `v1.21.1` and Kubernetes `v1.36` client
libraries, and is intended for the `ownsuall.com` platform.

## Published images

GitHub Actions tests every pull request to `main`. A push to `main` publishes
multi-architecture (`linux/amd64`, `linux/arm64`) images to:

```text
ghcr.io/fmurrie/godaddy-webhook:sha-<git-commit>
```

Images are immutable: this fork does not publish a `latest` tag. Platform
manifests must pin the image digest resolved from that commit. The former
Quay image and the generated legacy manifests/charts under `deploy/` are not
the supported installation path for this fork.

## Platform integration

The platform installs cert-manager and this webhook declaratively with Flux.
The DNS solver is identified by:

```yaml
groupName: acme.ownsuall.com
solverName: godaddy
```

The GoDaddy API token is stored only in an encrypted SOPS secret in the
platform repository. It is a single GoDaddy Personal Access Token (PAT) and must never
be committed, logged, copied to test fixtures, or passed as a command-line
argument. DNS-01 lets Let's Encrypt validate `*.apps.ownsuall.com` without
exposing the cluster on the public Internet.

The GitOps deployment will be added only after an image has been published and
its digest verified. Do not install the legacy Helm chart or apply
`deploy/webhook-all.yml` directly to the platform.

## Local development

Requirements:

- Go `1.26.0` or newer;
- Docker Buildx to build container images.

Run the hermetic unit tests:

```bash
make test
```

The upstream cert-manager conformance suite talks to real GoDaddy DNS. Use a
dedicated, restricted test token and a dedicated test zone. The credentials
are written only to a temporary test fixture and are not retained in the
repository:

```bash
export TEST_ZONE_NAME=example.ownsuall.com.
read -r -s GODADDY_TEST_TOKEN
export GODADDY_TEST_TOKEN
make test-conformance
unset GODADDY_TEST_TOKEN
```

The first conformance run downloads matching Kubernetes envtest assets to
`_out/`. It must not be used against a production zone.

Build a local development image:

```bash
make build
```

Override `IMAGE_NAME` and `IMAGE_TAG` explicitly if a local registry is
needed. The default is `ghcr.io/fmurrie/godaddy-webhook:dev`.
