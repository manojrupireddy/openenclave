// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "common.h"

ecall_dispatcher::ecall_dispatcher() : m_encrypt(true), m_header(NULL)
{
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);
}

int ecall_dispatcher::initialize(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    m_encrypt = encrypt;
    memset((void*)m_encryption_key, 0, ENCRYPTION_KEY_SIZE_IN_BYTES);

    int data = 0;
    

    /* Initialize and opt-in the RDRAND engine. */
    ENGINE_load_rdrand();
    m_eng = ENGINE_by_id("rdrand");
    if (m_eng == NULL)
    {
        goto exit;
    }

    if (!ENGINE_init(m_eng))
    {
        goto exit;
    }

    if (!ENGINE_set_default(m_eng, ENGINE_METHOD_RAND))
    {
        goto exit;
    }

    ret = process_encryption_header(encrypt, password, password_len, header);
    TRACE_ENCLAVE("MAN:: initialization of header done");
    if (ret != 0)
    {
        TRACE_ENCLAVE("process_encryption_header failed with %d", ret);
        goto exit;
    }

    TRACE_ENCLAVE("MAN:: Encryption header processed");
    if(!(m_encryption_cipher_ctx = EVP_CIPHER_CTX_new()))
        ret = -1;
    if(1 != EVP_EncryptInit_ex(m_encryption_cipher_ctx, EVP_aes_256_cbc(), NULL,m_encryption_key , m_operating_iv))
        ret = -1;
    
    if(!(m_decryption_cipher_ctx = EVP_CIPHER_CTX_new()))
        ret = -1;
    if(1 != EVP_DecryptInit_ex(m_decryption_cipher_ctx, EVP_aes_256_cbc(), NULL,m_encryption_key , m_operating_iv))
        ret = -1;
    
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t input_size)
{
    int ret = 0;
    int output_data_size = 0;
    int last_cipher_block_length = 0;
    
    if(m_encrypt)
    {
        if(1 != EVP_EncryptUpdate(m_encryption_cipher_ctx, output_buf, &output_data_size, input_buf, input_size))
            ret = -1;
        if(1 != EVP_EncryptFinal_ex(m_encryption_cipher_ctx, output_buf + output_data_size, &last_cipher_block_length))
            ret = -1;
        output_data_size += last_cipher_block_length; 
    }
    else
    {
        
        if(1 != EVP_DecryptUpdate(m_decryption_cipher_ctx, output_buf, &output_data_size, input_buf, input_size))
            ret = -1;
        if(1 != EVP_DecryptFinal_ex(m_decryption_cipher_ctx, output_buf + output_data_size, &last_cipher_block_length))
            ret = -1;
        output_data_size += last_cipher_block_length; 
    }
exit:
    return ret;
}

void ecall_dispatcher::close()
{
    ENGINE_finish(m_eng);
    ENGINE_free(m_eng);
    ENGINE_cleanup();
    if (m_encrypt)
    {
        oe_host_free(m_header);
        m_header = NULL;
    }
    EVP_CIPHER_CTX_free(m_encryption_cipher_ctx);
    EVP_CIPHER_CTX_free(m_decryption_cipher_ctx);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
