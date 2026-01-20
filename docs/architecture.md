# Core Concepts and Workflow

[中文文档](architecture_zh.md)

This page provides a detailed introduction to the core working model of TNG (Trusted Network Gateway), its remote attestation mechanisms, and the encryption protocols it employs. Understanding these concepts will help you better design network topologies and write configuration files before you start configuring and deploying TNG.

## Tunnel Model and Ingress/Egress

### Tunnel Model

In the classic TCP programming model, network communication can be simplified as a Client-Server model as shown below. The Client, as the active initiator of requests (TCP / HTTP), connects to a certain port listened to by the Server. At this point, the Client and Server communicate using plaintext or encrypted protocols such as TLS.

![Client-Server Model](diagrams/client_server_model.drawio.svg)

In a confidential computing environment, a pair of TNG instances can be deployed within the trusted domains of both parties. A secure channel is established between these TNG instances through Remote Attestation. Plaintext requests initiated by the Client are encrypted by TNG and sent through this secure channel to the TNG instance at the other end, which then forwards them to the Server. Similar to TCP / HTTP, this secure channel is duplex: when the Server finishes processing the request and returns a response, the response plaintext is also encrypted by TNG, returned to the Client-side TNG, decrypted, and then forwarded to the Client application.

![TNG Tunnel Model](diagrams/tng_tunnel_model.drawio.svg)

### Introduction to Ingress and Egress

In the above model, the Client and Server act as the active initiator and passive responder of the connection, with semantics of `connect()` and `accept()` respectively. Correspondingly, in TNG, we have designed two corresponding concepts for the secure channel: Ingress and Egress. Traffic from the active initiator (Client) enters the secure channel through the Ingress and flows out to the passive responder (Server) from the Egress.

Although there is a distinction between Ingress and Egress, both TNG instances are peer entities, and the established secure channel is duplex, allowing messages to be transmitted in either direction.

A TNG instance can be configured to act as an Ingress or an Egress. The main difference lies in how traffic is accessed. To facilitate integration with existing business processes, TNG provides multiple methods for accessing regular business traffic on both Ingress and Egress sides. This allows users to flexibly control the encryption and decryption process of traffic according to their needs without modifying existing applications.

> [!TIP]
> You can check the specific configuration parameters for [Ingress](configuration.md#ingress) and [Egress](configuration.md#egress) in the [Configuration Manual](configuration.md).

## Remote Attestation

In modern cloud computing environments, ensuring the authenticity of the identities of both communicating parties and the integrity of the runtime environment is crucial. TNG provides end-to-end robust trust assurance for data communication by introducing Remote Attestation mechanisms. Remote Attestation allows one party (the Attester) to prove the authenticity and integrity of its hardware and software environment to another party (the Verifier).

TNG plays a core role in Remote Attestation and can be an **Attester** or a **Verifier** depending on the configuration.

### Remote Attestation Roles

#### Attester: Proving "Who I Am" and "What I Did"

When TNG is configured as an Attester, it is responsible for generating and providing "trusted credentials" or "evidence" of its computing environment. This evidence includes hardware measurement values of the computing platform (e.g., TEE environment), hash values of software components at startup, and runtime configurations.

To achieve this, TNG interacts with a key component:
*   **Attestation Agent (AA)**: A proxy program running inside the TEE (Trusted Execution Environment). AA is responsible for interacting with the underlying secure hardware (such as Intel TDX, AMD SEV-SNP, CSV, etc.), collecting raw trust measurement data, and formatting this data into standard "evidence" for TNG to retrieve.

In this scenario, the Attester is like a "declarant" holding a "secure hardware-certified ID card" provided by AA to prove its innocence to the other party.

> [!TIP]
> For Attester configuration fields and examples, please refer to the [Attester section](configuration.md#attest) in the configuration manual.

#### Verifier: Verifying "Are You Trustworthy"

When TNG is configured as a Verifier, it is responsible for receiving and strictly reviewing the trusted evidence provided by the peer TNG (Attester). The Verifier conducts multi-faceted verification of the evidence based on preset security policies and trust rules to confirm the peer's identity authenticity and whether the runtime environment meets expectations and remains untampered.

To complete the complex evidence verification process, TNG works in coordination with another key component:
*   **Attestation Service (AS)**: An independent backend service, usually running in a highly trusted environment. AS receives the trusted evidence forwarded by the TNG Verifier and performs deep verification and analysis. This includes:
    *   **Evidence Format and Signature Verification**: Ensuring the integrity and trusted source of the evidence.
    *   **Platform Integrity Measurement Verification**: Comparing the hardware and software measurement values contained in the evidence with pre-defined "Trusted Baselines" to confirm the environment hasn't been illegally modified.
    *   **Policy Compliance Check**: Determining whether the remote environment meets specific security requirements based on defined Policies.

Only when the Attestation Service returns a successful verification result will the TNG Verifier be convinced that the peer is trustworthy and allow the establishment of a secure communication channel. In this scenario, the Verifier is like an "inspector" who hands the "ID card" provided by the peer to the AS, an "authoritative certification body," for authentication and decides whether to trust the other party based on the results.

> [!TIP]
> For Verifier configuration fields and examples, please refer to the [Verifier section](configuration.md#verify) in the configuration manual.

## Encryption Protocols and Security

TNG employs advanced encryption protocols to achieve communication security, implementing transport-layer or session-layer encryption by combining Remote Attestation and privacy protection mechanisms. Currently, two core encryption protocols are primarily supported to adapt to different application scenarios and security needs: RATS-TLS and OHTTP.

### RATS-TLS

**Principle**: Remote attestation mechanisms are integrated into the standard TLS 1.3 protocol handshake to transmit remote attestation evidence materials. A TLS session is officially established or maintained only when the remote attestation verification is successful, proving that the peer's runtime environment is authentic and trustworthy. This means even if an attacker can hijack the network, they cannot impersonate a legitimate TNG instance to communicate in an untrusted environment. TNG binds the remote attestation verification result with the TLS session lifecycle; if the environment is judged untrustworthy, the connection establishment process will terminate immediately.

**Applicable Scenarios**:
*   **Arbitrary TCP Traffic**: TNG's design allows it to transparently handle any application-layer traffic based on the TCP protocol. This means whether it's HTTP, database connections (such as MySQL, PostgreSQL), RPC protocols, or any custom TCP protocol, TNG can protect them through RATS-TLS.
*   **Using L4 Load Balancers**: Since RATS-TLS runs on top of the TCP protocol, it has good compatibility with the traditional TCP/IP stack. This means when deploying TNG, you can continue using existing Layer 4 load balancers (e.g., LVS, NAT-mode load balancers, or TCP/UDP load balancers from cloud service providers).

> [!TIP]
> RATS-TLS is the default communication protocol for TNG. See the [Remote Attestation](configuration.md#remote-attestation) section of the configuration manual for related configurations.

### OHTTP (Oblivious HTTP)

**Principle**: OHTTP enables encrypted transmission of client HTTP requests and responses. When used in conjunction with an OHTTP Relay service that forwards encrypted TNG requests, it can obscure the request source, thereby achieving stronger user privacy protection. For an introduction to OHTTP, please refer to the [RFC 9458 document](https://www.ietf.org/rfc/rfc9458.html).

**Applicable Scenarios**:
*   **Stateless HTTP Requests**: OHTTP's design naturally supports stateless HTTP requests. Each request is independent and does not rely on previous session information. This is ideal for RESTful API calls, static resource retrieval, etc.
*   **Using L7 Load Balancing**: TNG performs message-level encryption on HTTP at the session layer, and the ciphertext remains in HTTP message format. Therefore, encrypted TNG traffic can integrate seamlessly with existing Layer 7 load balancers (e.g., Nginx, HAProxy, Application Gateways, etc.). Additionally, TNG provides a set of custom parameter configurations that can adapt to existing L7 load balancer traffic distribution and routing rules, allowing TNG's secure channel to work without changing existing L7 infrastructure.

> [!TIP]
> For detailed configuration instructions and limitations of OHTTP, please refer to the [OHTTP section](configuration.md#ohttp) in the configuration manual.
