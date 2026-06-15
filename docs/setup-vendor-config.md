# Vendor Configuration Setup

This document describes how to configure cloud-provider-specific PCCS (Provisioning Certificate Caching Service) settings when using TNG's **builtin AS** mode.

## Background

When using builtin AS mode with **SGX or TDX** enclaves, the local quote verification process needs to fetch and verify provisioning certificates from a PCCS. The PCCS URL is configured in `/etc/sgx_default_qcnl.conf`.

If the PCCS URL is not set correctly for your cloud provider, quote verification will fail with:

```
tee_verify_quote failed: 0xe019
```

## The `setup-vendor-config` Tool

TNG ships with a `setup-vendor-config` tool to automatically configure `/etc/sgx_default_qcnl.conf` for supported cloud providers.

### Usage

```
setup-vendor-config <vendor> [options]
```

| Option | Description |
|---|---|
| `<vendor>` | Cloud provider name (required) |
| `--region REGION` | Cloud region ID (optional for some vendors) |
| `--internal` | Use VPC internal endpoint (requires `--region`) |
| `--dry-run` | Show what would be changed without applying |
| `--no-backup` | Skip creating a backup of the existing config |
| `--list` | List all supported vendors with details |
| `--help` | Show help message |

### Supported Vendors

| Vendor | Description | Default Region |
|---|---|---|
| `aliyun` | Alibaba Cloud SGX DCAP PCCS | `cn-hangzhou` |

### Examples

```sh
# Configure for Alibaba Cloud (uses default region cn-hangzhou)
setup-vendor-config aliyun

# Configure for a specific region
setup-vendor-config aliyun --region cn-beijing

# Use VPC internal endpoint (requires explicit --region)
setup-vendor-config aliyun --internal --region cn-hangzhou

# Preview changes without applying
setup-vendor-config aliyun --region cn-shanghai --dry-run

# List all supported vendors
setup-vendor-config --list
```

### Docker Usage

Run the tool inside the container before `tng launch`:

```sh
docker run -it --rm --privileged --network host --cgroupns=host \
  ghcr.io/inclavare-containers/tng:latest \
  sh -c 'setup-vendor-config aliyun && tng launch --config-content="..."'
```

> [!TIP]
> The `--region` flag is optional for Alibaba Cloud — `cn-hangzhou` works for all TDX instances. Use `--region` only if you need a different endpoint.

### VPC Internal Endpoint

> [!IMPORTANT]
> When `--internal` is specified, `--region` **must** be provided explicitly — the default region (`cn-hangzhou`) will not be used.

The `--internal` flag switches the PCCS URL to the VPC internal endpoint (`sgx-dcap-server-vpc.<region>.aliyuncs.com`), which uses Alibaba Cloud's internal network instead of the public internet. This provides lower latency and avoids public bandwidth charges when running inside a VPC.

```sh
# VPC internal endpoint for cn-hangzhou
setup-vendor-config aliyun --internal --region cn-hangzhou
```

## Manual Configuration

If your provider is not yet supported by the tool, manually edit `/etc/sgx_default_qcnl.conf`:

```sh
sudo sed -i.$(date "+%m%d%y") 's|PCCS_URL=.*|PCCS_URL=https://sgx-dcap-server.<region>.<provider-domain>/sgx/certification/v4/|' /etc/sgx_default_qcnl.conf
```

Replace `<region>` and `<provider-domain>` with your cloud provider's PCCS endpoint. Consult your provider's confidential computing documentation for the correct URL.

## Adding a New Vendor

To add support for a new vendor, edit `scripts/setup-vendor-config` and add three variables following the existing pattern:

```bash
VENDOR_PCCS_URL_<name>="https://<pccs-endpoint>/__REGION__/<path>"
VENDOR_REQUIRES_REGION_<name>="false"   # or "true" if region is mandatory
VENDOR_DEFAULT_REGION_<name>="<region>"
```

Then add the vendor name to the `SUPPORTED_VENDORS` list.
