// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// clang-format off

// clang-format on

#include <openenclave/internal/print.h>
#include <openenclave/internal/raise.h>

oe_result_t enclave_identity_verifier(oe_identity_t* identity, void* arg);

oe_result_t generate_key_pair(
    uint8_t** public_key,
    size_t* public_key_size,
    uint8_t** private_key,
    size_t* private_key_size);

#define SERVER_IP "127.0.0.1"

#define CLIENT_REQUEST_PAYLOAD_SIZE 18

#define CLIENT_GET_REQUEST "GET / HTTP/1.0\r\n\r\n"

#define SERVER_HTTP_RESPONSE                             \
    "HTTP/1.0 200 OK\r\nContent-Type: text/html\r\n\r\n" \
    "<h2>mbed TLS Test Server</h2>\r\n"                  \
    "<p>Successful connection using: %s</p>\r\n"         \
    "A message from TLS server inside enclave\r\n"

#define SERVER_RESPONSE_PAYLOAD_SIZE 194