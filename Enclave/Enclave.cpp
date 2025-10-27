#include "Enclave_t.h"

#include <sgx_trts.h>
#include <sgx_report.h>
#include <sgx_utils.h>

 sgx_status_t ecall_get_report(
    const uint8_t* pTrgInfo,
    const uint8_t* pReportData,
    uint8_t* pReport
)
{
    sgx_status_t ret = sgx_create_report(
        (const sgx_target_info_t*) pTrgInfo,
        (const sgx_report_data_t*) pReportData,
        (sgx_report_t*) pReport
    );
    return ret;
}
