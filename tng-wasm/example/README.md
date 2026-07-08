# Running the Static Example

The `tng-wasm/example/` directory contains an example page that uses the TNG SDK to send encrypted requests. The example requires a confidential computing server instance and a local computer. The following describes how to run the example.

> [!NOTE]
> The example page references the SDK build output via `../pkg/tng_wasm.js`, so no manual file copying is required — as long as the SDK has been built locally (output in `tng-wasm/pkg/`), serve the `tng-wasm/` root directory with any static server.

### 1. Prepare the Server-side Service

Use [dummyhttp](https://github.com/svenstaro/dummyhttp), a simple HTTP server program, to simulate our backend service. We need to install and run it.

Installation

```sh
cargo install dummyhttp --locked
```

Run this HTTP server and make it listen on port 30001. Now we have a backend HTTP service listening on port 30001.

```sh
dummyhttp -p 30001 -vvvv
```

> [!NOTE]
> You can use the curl command on the local computer to test direct access to this HTTP server to check network connectivity.

### 2. Compile and Install TNG on the Server Side

Build the RPM package

```sh
make create-tarball
make rpm-build
```

The artifacts will be placed in `~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm`, which you can install as follows:

```sh
yum install ~/rpmbuild/RPMS/*/trusted-network-gateway-*.rpm -y
```

If you want to build the container version of TNG:

```sh
# First install podman
yum install podman podman-docker -y
# Build the container image
docker build -t tng:test .
```

This will produce a container image named `tng:test`.

### 3. Run Attestation-Agent on the Server Side

You can choose to install attestation-agent from the yum repository or compile and deploy your own attestation-agent.

```sh
yum install -y attestation-agent
```

Run

```sh
RUST_LOG=debug attestation-agent --attestation_sock unix:///run/confidential-containers/attestation-agent/attestation-agent.sock
```

### 4. Run TNG on the Server Side

```sh
tng launch --config-content='
    {
        "add_egress": [
            {
                "netfilter": {
                    "capture_dst": {
                        "port": 30001
                    },
                    "capture_local_traffic": true
                },
                "ohttp": {},
                "attest": {
                    "aa_addr": "unix:///run/confidential-containers/attestation-agent/attestation-agent.sock"
                }
            }
        ]
    }'
```

> [!NOTE]
>
> - Currently, the TNG SDK only supports server-side verification, so you must provide the `"attest"` option
> - As shown above, you need to add an `"ohttp": {}` entry in the TNG configuration to enable using OHTTP as the encryption protocol (instead of rats-tls) for bidirectional encrypted traffic transmission.

### 5. Run the Attestation Service Instance

You need to prepare an Attestation Service instance that exposes a RESTful HTTP interface. This can be achieved by installing the `trustee` package from the yum repository or compiling and deploying your own `restful-as`.

A reference run command is as follows:

```sh
cat <<EOF > /tmp/config_with_cert.json
{
    "work_dir": "/var/lib/attestation-service/",
    "rvps_config": {
        "type": "BuiltIn",
        "storage": {
            "type": "LocalFs"
        }
    },
    "attestation_token_broker": {
        "type": "Simple",
        "duration_min": 5
    }
}
EOF

RUST_LOG=debug restful-as --socket 0.0.0.0:9080 --config-file /tmp/config_with_cert.json

# Since restful-as natively does not support CORS configuration, here we run a CORS proxy service (https://github.com/bulletmark/corsproxy) that forwards requests from port 8080 to the real Attestation Service.
podman run -it --rm --net=host docker.io/bulletmark/corsproxy:latest 8080=http://127.0.0.1:9080
```

The above will expose an Attestation Service on port 8080.

> [!NOTE]
> Since the TNG SDK needs to initiate requests to the Attestation Service instance in the browser, please ensure you handle the CORS rules properly.

Here is an example:

### 6. Compile the TNG SDK

```sh
make wasm-build-debug
```

This will produce the corresponding `.wasm` and `.js` files in the `tng-wasm/pkg/` directory.

### 7. Modify the Frontend Page Code

Please modify the following content in [index.html](index.html) as needed:

URL of the backend service to access:

```js
const url = "http://127.0.0.1:30001/foo/bar?baz=qux";
```

Attestation Service URL and policy ID for verification:

```js
const asAddr = "http://127.0.0.1:8080/";
const policyIds = ["default"];
```

### 8. Run the Frontend Service on the Server Side

The simplest way is to use the make target provided by the repository (it automatically adds the COOP/COEP headers required for cross-origin isolation):

```sh
make wasm-example-serve
```

Then visit `http://<server ip>:8082/example/`.

If you want to start the static service manually, install [miniserve](https://github.com/svenstaro/miniserve):

```sh
cargo +nightly-2025-07-07 install miniserve --locked
miniserve ./tng-wasm \
    --header "Cross-Origin-Opener-Policy:same-origin" \
    --header "Cross-Origin-Embedder-Policy:require-corp" \
    --port 8082
```

Then visit `http://<server ip>:8082/example/`.

> [!NOTE]
>
> - [`miniserve`](https://github.com/svenstaro/miniserve) is a pure static resource server. It's no different from Nginx or Python's http.server, and you can use other components as alternatives.

### 9. Access in the Browser

Open a browser on the local computer and visit `http://<server ip>:8082/example/`. You can view the request response logs in F12.
