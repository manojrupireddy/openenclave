// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/report.h>
#include "../common.h"
#include "config_id_t.h"

oe_result_t enclave_test_config_id()
{
    OE_TRACE_INFO("enclave_config_id_test_kss_properties invoked\n");
    oe_result_t result = OE_UNEXPECTED;
    size_t report_size = OE_MAX_REPORT_SIZE;
    uint8_t* remote_report = NULL;
    oe_report_header_t* header = NULL;
    sgx_quote_t* quote = NULL;

    result = oe_get_report(
        OE_REPORT_FLAGS_REMOTE_ATTESTATION,
        NULL,
        0,
        NULL,
        0,
        (uint8_t**)&remote_report,
        &report_size);

    if (result == OE_OK)
    {
        OE_TRACE_INFO("========== Got report, size = %zu\n", report_size);

        header = (oe_report_header_t*)remote_report;
        quote = (sgx_quote_t*)header->report;

        sgx_report_body_t* report_body =
            (sgx_report_body_t*)&quote->report_body;

        if (memcmp(
                report_body->configid,
                original_config_id,
                sizeof(original_config_id)))
        {
            OE_TRACE_WARNING("========== Read wrong config id from the report");
            result = OE_REPORT_PARSE_ERROR;
        }
        if (report_body->configsvn != original_config_svn)
        {
            OE_TRACE_WARNING(
                "========== Read wrong config svn from the report");
            result = OE_REPORT_PARSE_ERROR;
        }
    }
    return result;
}

OE_SET_ENCLAVE_SGX_KSS(
    1, /* ProductID */
    1, /* SecurityVersion */
    {0},
    {0},
    true, /* Debug */
    1024, /* NumHeapPages */
    64,   /* NumStackPages */
    1);   /* NumTCS */
