// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "common.h"
#include "encryptor.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define SALT_SIZE_IN_BYTES 16 // Length of salt size

void ecall_dispatcher::dump_data(
    const char* name,
    unsigned char* data,
    size_t data_size)
{
    TRACE_ENCLAVE("Data name: %s", name);
    for (size_t i = 0; i < data_size; i++)
    {
        TRACE_ENCLAVE("[%ld]-0x%02X", i, data[i]);
    }
    TRACE_ENCLAVE("\n");
}

// Compute the sha256 hash of given data.
int ecall_dispatcher::Sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t sha256[32])
{
    return 0;
}

// This routine uses the mbed_tls library to derive an AES key from the input
// password and produce a password based key. Note : A set of hardcoded salt
// values are used here for the purpose simplifying this sample, which caused
// this routine to return the same key when taking the same password. This saves
// the sample from having to write salt values to the encryption header. In a
// real world application, randomly generated salt values are recommended.
int ecall_dispatcher::generate_password_key(
    const char* password,
    unsigned char* key,
    unsigned int key_len)
{
    return 0;
}

// Generate an encryption key: this is the key used to encrypt data
int ecall_dispatcher::generate_encryption_key(
    unsigned char* key,
    unsigned int key_len)
{
    return 0;
}

// The encryption key is encrypted before it was written back to the encryption
// header as part of the encryption metadata. Note: using fixed initialization
// vector (iv) is good enough because its used only for the purpose of
// encrypting encryption key, just once.
int ecall_dispatcher::cipher_encryption_key(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* encrypt_key,
    unsigned char* output_data,
    unsigned int output_data_size)
{
    return 0;
}

// For an encryption operation, the encryptor creates encryption metadata for
// writing back to the encryption header, which includes the following fields:
// digest: a hash value of the password
// key: encrypted version of the encryption key
//
// Operations involves the following operations:
//  1)derive a key from the password
//  2)produce a encryption key
//  3)generate a digest for the password
//  4)encrypt the encryption key with a password key
//
int ecall_dispatcher::prepare_encryption_header(
    encryption_header_t* header,
    string password)
{
    return 0;
}

// Parse an input header for validating the password and getting the encryption
// key in preparation for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a encryption key from the password
//  3)decrypt the encryption key with a password key
int ecall_dispatcher::parse_encryption_header(
    encryption_header_t* header,
    string password)
{
    return 0;
}

int ecall_dispatcher::process_encryption_header(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    return 0;
}
