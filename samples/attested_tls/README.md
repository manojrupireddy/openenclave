## Prerequisites
 The audience is assumed to be familiar:
 [What is an Attested TLS channel](AttestedTLSREADME.md#what-is-an-attested-tls-channel)

# The Attested TLS sample

It has the following properties:

- Demonstrates attested TLS feature
  - between two enclaves
  - between an enclave application and a non enclave application
- Use of mbedTLS/OpenSSL crypto libraries within enclaves for TLS
- Developer can select mbedTLS/OpenSSL crypto library by setting build time configuration variable `OE_CRYPTO_LIB` in Makefiles [here 1](Makefile#L8) or [here 2](CMakeLists.txt#L10) to `mbedtls` or `openssl`. Note that `OE_CRYPTO_LIB` is case sensitive and should be set to either `mbedtls` or `openssl`.
- Please check recommended configurations and practices to follow [here](#openssl-recommended-configurations-for-tls-communication) when using OpenSSL crypto library.
- Enclave APIs used:q
  - oe_get_attestation_certificate_with_evidence
  - oe_free_attestation_certificate
  - oe_verify_attestation_certificate_with_evidence

**Note: Currently this sample only works on SGX-FLC systems.** The underlying SGX library support for end-to-end remote attestation is required but available only on SGX-FLC system. There is no plan to back port those libraries to either SGX1 system or software emulator.

## Overall Sample Configuration

In first part of this sample, there are two enclave applications in this sample: one for hosting an TLS client inside an enclave and the other one for an TLS server.

 ![Attested TLS channel between two enclaves](tls_between_enclaves.png)

In the 2nd part of this sample, there is one regular application functioning as a non-enclave TLS client and an enclave application
instantiating an enclave which hosts an TLS server.

 ![Attested TLS channel between a non enclave application and an enclave](tls_between_non_enclave_enclave.png)

Note: Both of them can run on the same machine or separate machines.

### Server application
  - Host part (tls_server_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_server_enclave.signed)
    - Calls oe_get_attestation_certificate_with_evidence to generate an certificate
    - Use Mbedtls/OpenSSL API to configure an TLS server after configuring above certificate as the server's certificate
    - Launch a TLS server and wait for client connection request
    - Read client payload and reply with server payload
  - How to launch a server instance
```
../server/host/tls_server_host ../server/enc/tls_server_enc.signed -port:12341
```
### Enclave Client application
  - Host part (tls_client_host)
    - Instantiate an enclave before transitioning the control into the enclave via an ecall.
  - Enclave (tls_client_enclave.signed)
    - Calls oe_get_attestation_certificate_with_evidence to generate an certificate
    - Use Mbedtls/OpenSSL API to configure an TLS client after configuring above certificate as the client's certificate
    - Launch a TLS client and connect to the server
    - Send client payload and wait for server's payload
  - How to launch a client instance
```
../client/host/tls_client_host ../client/enc/tls_client_enclave.signed -server:localhost -port:12341
```

### Non-enclave Client application
 - When used in this scenario, this non-enclave client is assumed to be a trusted party holding secrets and only shares it with the server after the server is validated
 - Connect to server port via socket
 - Use OpenSSL API to configure a TLS client
 - Call oe_verify_attestation_certificate_with_evidence to validate server's certificate
 - Send client payload and wait for server's payload

```
../client/tls_non_enc_client -server:localhost -port:12341
```

## Build and run

To build and run the samples, refer to documentation in the main [README file](../README.md#building-the-samples.md).

Note: This sample uses an OE SDK customized version of mbedtls library for TLS channel connection when `OE_CRYPTO_LIB` is set to `mbedtls` in Makefiles. It has MBEDTLS_NET_C component enabled, which has a dependency on the newly added [socket support](../../docs/UsingTheIOSubsystem.md#socketh) in 0.6.0 OE SDK release (for more details see [Using the Open Enclave I/O subsystem](../../docs/UsingTheIOSubsystem.md#opting-in) for details). So in order to build successfully, you would need to link with liboehostsock and libhostresolver libraries to satisfy the dependency.

### Running attested TLS server in loop
By default the server exits after completing a TLS session with a client. `-server-in-loop` run-time option changes this behavior to allow the TLS server to handle multiple client requests.

On Linux:

```bash
./server/host/tls_server_host ./server/enc/tls_server_enc.signed -port:12341 -server-in-loop
or
make run-server-in-loop
```

On Windows after building the sample as described in the [README file](../README.md#building-the-samples.md):

```cmd
.\server\host\tls_server_host .\server\enc\tls_server_enc.signed -port:12341 -server-in-loop
```
### OpenSSL recommended configurations for TLS communication

  Open Enclave's security guidance recommends to use only subset of cipher suites, elliptic curve algorithms and TLS protocols available in the OpenSSL library. The recommended algorithms and protocols are listed below. Enclave application developers can use [`initalize_ssl_context`](common/openssl_utility.cpp#L118) method to configure the SSL_CTX to limit the algorithms and protocols to below list. In Attested TLS sample application, server and client modules invoke the method `initalize_ssl_context` [here](server/enc/openssl_server.cpp#L147) and [here](client/enc/openssl_client.cpp#L200) respectively to account for mentioned recommendations. It is strongly recommended that the application developers uses similar method to configure the SSL_CTX and limit the available ciphersuites and elliptic curve algorithms to below list.

  ##### Recommended configurations for TLS communication

  - TLS protocol versions
    - TLS 1.2
    - TLS 1.3
  - TLS 1.3 cipher suites:
    - TLS13-AES-256-GCM-SHA384
    - TLS13-AES-128-GCM-SHA256
  - TLS 1.2 cipher suites:
    - ECDHE-ECDSA-AES128-GCM-SHA256
    - ECDHE-ECDSA-AES256-GCM-SHA384
    - ECDHE-RSA-"AES128-GCM-SHA256
    - ECDHE-RSA-AES256-GCM-SHA384
    - ECDHE-ECDSA-AES128-SHA256
    - ECDHE-ECDSA-AES256-SHA384
    - ECDHE-RSA-AES128-SHA256
    - ECDHE-RSA-AES256-SHA384
  - Elliptic curve algorithms
    - P-521
    - P-384
    - P-256