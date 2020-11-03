// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openssl_utility.h"
#include <stdio.h>
#include <string.h>
#include "tls_e2e_t.h"

extern struct tls_control_args g_control_config;

oe_result_t generate_certificate_and_pkey(X509*& cert, EVP_PKEY*& pkey)
{
    oe_result_t result = OE_FAILURE;
    SSL_CTX_set_ecdh_auto(ctx, 1);
    uint8_t* output_cert = NULL;
    size_t output_cert_size = 0;
    uint8_t* private_key_buf = NULL;
    size_t private_key_buf_size = 0;
    uint8_t* public_key_buf = NULL;
    size_t public_key_buf_size = 0;
    const unsigned char* cert_buf_ptr = NULL;

    result = generate_key_pair(
        &public_key_buf,
        &public_key_buf_size,
        &private_key_buf,
        &private_key_buf_size);

    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));
    OE_TRACE_INFO("public_key_buf_size:[%ld]\n", public_key_buf_size);
    OE_TRACE_INFO("public key used:\n[%s]", public_key_buf);

    result = oe_generate_attestation_certificate(
        (const unsigned char*)"CN=Open Enclave SDK,O=OESDK TLS,C=US",
        private_key_buf,
        private_key_buf_size,
        public_key_buf,
        public_key_buf_size,
        &output_cert,
        &output_cert_size);
    OE_CHECK_MSG(result, " failed with %s\n", oe_result_str(result));

    // temporary buffer required as if d2i_x509 call is successful cert_buf_ptr
    // is incremented to the byte following the parsed data. sending
    // cert_buf_ptr as argument will keep output_cert pointer undisturbed.
    cert_buf_ptr = output_cert;

    if ((cert = d2i_X509(NULL, &cert_buf_ptr, (long)output_cert_size)) == NULL)
    {
        OE_TRACE_ERROR(
            TLS_SERVER
            "Failed to convert DER fromat certificate to X509 structure\n");
        goto done;
    }

    if ((pkey = PEM_read_bio_PrivateKey(
             BIO_new_mem_buf((void*)private_key_buf, -1), NULL, 0, NULL)) ==
        NULL)
    {
        OE_TRACE_ERROR(
            TLS_SERVER
            "Failed to convert private key buffer into EVP_KEY format\n");
        goto done;
    }

    result = OE_OK;
done:
    cert_buf_ptr = NULL;
    oe_free_key(private_key_buf, private_key_buf_size, NULL, 0);
    oe_free_key(public_key_buf, public_key_buf_size, NULL, 0);
    oe_free_attestation_certificate(output_cert);
    return result;
}

// The return value of verify_callback controls the strategy of the further
// verification process. If verify_callback returns 0, the verification process
// is immediately stopped with "verification failed" state and A verification
// failure alert is sent to the peer and the TLS/SSL handshake is terminated. If
// verify_callback returns 1, the verification process is continued.
int cert_verify_callback(int preverify_ok, X509_STORE_CTX* ctx)
{
    int ret = 0;
    int der_len = 0;
    unsigned char* der = nullptr;
    unsigned char* buff = nullptr;
    oe_result_t result = OE_FAILURE;
    X509* crt = nullptr;
    int err = X509_V_ERR_UNSPECIFIED;

    printf(
        TLS_SERVER "verify_callback called with preverify_ok=%d\n",
        preverify_ok);
    crt = X509_STORE_CTX_get_current_cert(ctx);
    if (crt == nullptr)
    {
        printf(TLS_SERVER "failed to retrieve certificate\n");
        goto done;
    }

    if (preverify_ok == 0)
    {
        err = X509_STORE_CTX_get_error(ctx);
        if (err == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        {
            // A self-signed certificate is expected, return 1 to continue the
            // verification process
            printf(TLS_SERVER "self-signed certificated detected\n");
            ret = 1;
            goto done;
        }
    }

    // convert a cert into a buffer in DER format
    der_len = i2d_X509(crt, nullptr);
    buff = (unsigned char*)malloc(der_len);
    if (buff == nullptr)
    {
        printf(TLS_SERVER "malloc failed (der_len=%d)\n", der_len);
        goto done;
    }
    der = buff;
    der_len = i2d_X509(crt, &buff);
    if (der_len < 0)
    {
        printf(TLS_SERVER "i2d_X509 failed(der_len=%d)\n", der_len);
        goto done;
    }

    if (g_control_config.fail_oe_verify_attestation_certificate)
        goto done;
    // verify tls certificate
    result = oe_verify_attestation_certificate(
        der, der_len, enclave_identity_verifier, nullptr);

    if (result != OE_OK)
    {
        printf(TLS_SERVER "result=%s\n", oe_result_str(result));
        goto done;
    }
    ret = 1;
done:

    if (der)
        free(der);

    if (err != X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
    {
        printf(
            TLS_SERVER "verifying SGX certificate extensions ... %s\n",
            ret ? "succeeded" : "failed");
    }
    return ret;
}

int read_from_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int ret = -1;
    unsigned char buf[200];
    int bytes_read = 0;
    do
    {
        int len = sizeof(buf) - 1;
        memset(buf, 0, sizeof(buf));
        bytes_read = SSL_read(ssl_session, buf, (size_t)len);

        if (bytes_read <= 0)
        {
            int error = SSL_get_error(ssl_session, bytes_read);
            if (error == SSL_ERROR_WANT_READ)
                continue;

            printf("Failed! SSL_read returned error=%d\n", error);
            ret = bytes_read;
            break;
        }

        printf(" %d bytes read from session peer\n", bytes_read);

        // check to see if received payload is expected
        if ((bytes_read != payload_length) ||
            (memcmp(payload, buf, bytes_read) != 0))
        {
            printf(
                "ERROR: expected reading %lu bytes but only "
                "received %d bytes\n",
                payload_length,
                bytes_read);
            ret = bytes_read;
            goto exit;
        }
        else
        {
            printf(" received all the expected data from the session peer\n\n");
            ret = 0;
            break;
        }

        printf("Verified: the contents of peer payload were expected\n\n");
    } while (1);

exit:
    return ret;
}

int write_to_session_peer(
    SSL*& ssl_session,
    const char* payload,
    size_t payload_length)
{
    int bytes_written = 0;
    int ret = 0;

    while ((bytes_written = SSL_write(ssl_session, payload, payload_length)) <=
           0)
    {
        int error = SSL_get_error(ssl_session, bytes_written);
        if (error == SSL_ERROR_WANT_WRITE)
            continue;
        printf("Failed! SSL_write returned %d\n", error);
        ret = bytes_written;
        goto exit;
    }

    printf("%lu bytes written to session peer \n\n", payload_length);
exit:
    return ret;
}