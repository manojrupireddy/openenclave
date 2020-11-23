// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.
#include "cert_verify_config.h"

oe_result_t verify_claim_value(const oe_claim_t* claim)
{
    oe_result_t result = OE_OK;
    printf("\nverify unique_id:\n");
    for (size_t i = 0; i < claim->value_size; i++)
        printf("0x%x ", (uint8_t)claim->value[i]);
    printf("\n");
    return result;
}
