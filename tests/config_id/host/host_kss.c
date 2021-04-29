// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "../common.h"
#include "../host/sgx/cpuid.h"
#include "config_id_u.h"

static bool _is_kss_supported()
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(0x12, 0x1, &eax, &ebx, &ecx, &edx);

    // Check if KSS (bit 7) is supported by the processor
    if (!(eax & (1 << 7)))
        return false;
    else
        return true;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc < 2)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH [--host-threads n] [--enclave-threads n] "
            "[--ecalls]\n",
            argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if (_is_kss_supported()) // This test case gets executed only on kss
                             // supported SGX family
    {
        oe_sgx_enclave_setting_config_data config_data_setting = {
            {0}, original_config_svn, false /* ignore_if_unsupported */};
        memcpy(
            config_data_setting.config_id,
            original_config_id,
            sizeof(config_data_setting.config_id));
        oe_enclave_setting_t mandatory_settings;
        mandatory_settings.setting_type = OE_SGX_ENCLAVE_CONFIG_DATA;
        mandatory_settings.u.config_data = &config_data_setting;
        result = oe_create_config_id_enclave(
            argv[1],
            OE_ENCLAVE_TYPE_SGX,
            flags,
            &mandatory_settings,
            1,
            &enclave);
        OE_TEST(result == OE_OK);
        enclave_test_config_id(enclave, &result);
        OE_TEST(result == OE_OK);
    }

    printf("=== passed all tests (config_id_kss)\n");
    return 0;
}
