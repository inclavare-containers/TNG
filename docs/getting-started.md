# Your first request through TNG

[中文](getting-started_zh.md) · [Documentation](README.md)

Start with a local RATS-TLS non-multiplexed tunnel, then enable remote attestation for a TEE deployment. The local demo encrypts the tunnel but sets `no_ra: true` on both endpoints. It does not authenticate a trusted environment or protect against an active peer impersonator. Keep all listeners on loopback and use this configuration only for local development.

## Prerequisites

- A prebuilt `tng` binary for your system from [Releases](https://github.com/inclavare-containers/TNG/releases), extracted, made executable with `chmod +x` on Unix systems, and added to `PATH`. Check it with `tng --version`.
- Git, Python 3 and curl. You need three terminals in the repository root.
- Free TCP ports 38080, 38081 and 38082 on `127.0.0.1`.

This example uses port mapping. It needs no root permissions, network interception, TEE or attestation service. For a source build, follow the [developer guide](developer.md).

```sh
git clone https://github.com/inclavare-containers/TNG.git
cd TNG
```

## Start the backend

Run in terminal 1:

```sh
cd examples/quickstart/backend
python3 -m http.server 38080 --bind 127.0.0.1
```

The backend serves the repository's `hello.txt` file. Leave it running.

## Start the tunnel

Run in terminal 2, from the repository root:

```sh
tng launch --config-file examples/quickstart/local.json
```

One TNG process runs both endpoints for this demonstration:

```text
curl → 127.0.0.1:38082   → 127.0.0.1:38081   → 127.0.0.1:38080
       TNG Ingress        TNG Egress          Python backend
       └── TLS encrypted ──┘
```

Ingress is where traffic enters the tunnel; Egress is where it leaves. The application links outside that segment carry plain HTTP here. Inspect [local.json](../examples/quickstart/local.json) for the complete `add_ingress` and `add_egress` configuration. Both explicitly select `rats_tls.multiplex: false` and `no_ra: true`.

## Make a request and clean up

Run in terminal 3:

```sh
curl --fail --noproxy '*' http://127.0.0.1:38082/hello.txt
```

Expected response body:

```text
Hello through TNG.
```

Press Ctrl+C in terminals 2 and 1 to stop TNG and the backend. No system network rules or persistent services are created.

If startup reports a port already in use, stop your previous demo processes or choose three unused ports in the JSON, backend command and request URL. If curl cannot connect, check that both processes are still running and that each terminal uses the repository root. `--noproxy '*'` bypasses any proxy environment variables for this loopback request.

## Enable real remote attestation

For a real deployment, run Egress inside the TEE with the backend and run Ingress in the caller's environment. Split the two entries into separate configuration files, replace loopback tunnel addresses with your deployment addresses, and restrict access to the intended peers. Remove `no_ra` on both sides.

Configure `attest` on Egress to collect evidence from an Attestation Agent inside the TEE. Configure `verify` on Ingress to verify that evidence against your policy, using the built-in verifier or an external service. The [remote attestation adoption guide](remote_attestation.md#adoption-guide) explains the fields and dependencies; [HTTP proxy to a confidential node](scenarios/02-http-proxy-single/README.md) supplies a complete deployment example.

The built-in `hardware_only` policy checks hardware evidence, without comparing workload measurements to your chosen baseline. Use an appropriate measurement policy and reference values when your trust decision includes which workload may run. Check both a permitted deployment and a deliberately mismatching policy before using the service; a rejected peer must not reach the backend. See [remote attestation](remote_attestation.md) for policy choices and prerequisites.

## Choose the next integration

- [Scenarios](scenarios/README.md) cover transparent proxies, confidential AI inference, clusters and relay privacy.
- [SDKs and integration choices](README.md#choose-an-integration) cover browser, Python, Go and existing processes.
- [Configuration](configuration.md) covers port mapping, proxies, UDP over QUIC and protocol options.
