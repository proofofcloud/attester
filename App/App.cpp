#include "Enclave_u.h"
#include <vector>
#include <cstdio>
#include <stdexcept>
#include <cstdarg>
#include <iostream>

#include <sgx_uae_quote_ex.h>
#include <sgx_ql_lib_common.h>
#include <sgx_dcap_ql_wrapper.h>
#include <sgx_dcap_quoteverify.h>

void ThrowF(const char* fmt, ...)
{
    char buf[0x400];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);

    throw std::runtime_error(buf);    
}

void TestRet_Hex(uint32_t status, uint32_t good_status, const char* op_name)
{
    if (status != good_status)
        ThrowF("%s failed: 0x%08x", op_name, status);
}

void TestRet(sgx_status_t status, const char* op_name)
{
    TestRet_Hex(static_cast<uint32_t>(status), static_cast<uint32_t>(SGX_SUCCESS), op_name);
}

void TestRet(quote3_error_t status, const char* op_name)
{
    TestRet_Hex(static_cast<uint32_t>(status), static_cast<uint32_t>(SGX_QL_SUCCESS), op_name);
}


std::vector<uint8_t> ProduceQuote(sgx_enclave_id_t eid, const sgx_report_data_t& rd)
{
    sgx_target_info_t trg_info;
    TestRet(sgx_qe_get_target_info(&trg_info), "sgx_qe_get_target_info");

    sgx_report_t rep;
    sgx_status_t retVal = SGX_SUCCESS;

    sgx_status_t ret = ecall_get_report(eid,
        &retVal,
        (const uint8_t*) &trg_info,
        (const uint8_t*) &rd,
        (uint8_t*) &rep);

    TestRet(ret, "ecall_get_report");
    TestRet(retVal, "ecall_get_report retval");


    uint32_t nQuoteSize = 0;
    TestRet(sgx_qe_get_quote_size(&nQuoteSize), "sgx_qe_get_quote_size");

    if (!nQuoteSize)
        throw std::runtime_error("quote size deduced as 0");

    std::vector<uint8_t> vQ;
    vQ.resize(nQuoteSize);

    TestRet(sgx_qe_get_quote(&rep, nQuoteSize, &vQ.front()), "sgx_qe_get_quote");

    return vQ;
}

const char* ParseQvRes(sgx_ql_qv_result_t x)
{
    switch (x)
    {
#define STD_CASE(val) case sgx_ql_qv_result_t::SGX_QL_QV_RESULT_##val: return #val;

    STD_CASE(OK)
    STD_CASE(CONFIG_NEEDED)
    STD_CASE(OUT_OF_DATE)
    STD_CASE(OUT_OF_DATE_CONFIG_NEEDED)
    STD_CASE(INVALID_SIGNATURE)
    STD_CASE(REVOKED)
    STD_CASE(UNSPECIFIED)
    STD_CASE(SW_HARDENING_NEEDED)
    STD_CASE(CONFIG_AND_SW_HARDENING_NEEDED)
    STD_CASE(TD_RELAUNCH_ADVISED)
    STD_CASE(TD_RELAUNCH_ADVISED_CONFIG_NEEDED)

#undef STD_CASE

    default: // suppress warning
        break;

    }

    return nullptr;
}

uint8_t Ch2Hex(char ch)
{
    if ((ch >= '0') && (ch <= '9'))
        return static_cast<uint8_t>(ch - '0');

    if ((ch >= 'a') && (ch <= 'f'))
        return static_cast<uint8_t>(ch + 0xa - 'a');

    if ((ch >= 'A') && (ch <= 'F'))
        return static_cast<uint8_t>(ch + 0xa - 'A');

    ThrowF("invalid hex char: %c", ch);
    return 0; // unreachable
}

void ScanHex(uint8_t* pDst, uint32_t nDst, const char* sz)
{
    uint32_t ret = 0;
    for (; ret < nDst; ret++)
    {
        auto n0 = Ch2Hex(*sz++);
        auto n1 = Ch2Hex(*sz++);
        pDst[ret] = (n0 << 4) | n1;
    }
}

char Hex2Ch(uint8_t x)
{
    return (x <= 9) ?
        static_cast<char>('0' + x) :
        static_cast<char>('A' + (x - 0xa));
}

void Bin2Hex(char* sz, const uint8_t* p, uint32_t n)
{
    while (n--)
    {
        auto x = *p++;
        *sz++ = Hex2Ch(x >> 4);
        *sz++ = Hex2Ch(x & 0xf);
    }
}

void PrintHex(const uint8_t* p, uint32_t n)
{
    const uint32_t nNaggle = 64;
    char szBuf[nNaggle * 2];

    while (n >= nNaggle)
    {
        Bin2Hex(szBuf, p, nNaggle);
        fwrite(szBuf, 1, nNaggle * 2, stdout);

        p += nNaggle;
        n -= nNaggle;
    }

        Bin2Hex(szBuf, p, n);
        fwrite(szBuf, 1, n * 2, stdout);
}

template <typename T>
void PrintHex_T(const T& val)
{
    PrintHex((const uint8_t*) &val, sizeof(val));
}

std::vector<uint8_t> GetQuote(const char* szChallenge)
{
    sgx_report_data_t rd;

    auto len = (uint32_t) strlen(szChallenge);
    if (len & 1)
        throw std::runtime_error("challenge len must be even");
    len /= 2;

    if (len > sizeof(rd.d))
        ThrowF("challenge text len must not exceed %u", sizeof(rd.d)*2);

    ScanHex(rd.d, len, szChallenge);
    memset(rd.d + len, 0, sizeof(rd.d) - len);


    sgx_enclave_id_t eid = 0;
    TestRet(sgx_create_enclave("enclave.signed.so", 0, nullptr, nullptr, &eid, nullptr), "sgx_create_enclave");

    auto vQ = ProduceQuote(eid, rd);

    printf("RAW Quote: ");
    PrintHex(&vQ.front(), (uint32_t) vQ.size());
    printf("\n");

    // sgx_destroy_enclave(eid);

    return vQ;
}

struct MemSlice
{
    const uint8_t* m_p;
    uint32_t m_n;

    void EnsureHave(uint32_t n)
    {
        if  (n > m_n)
            ThrowF("Underflow: need %u, have %u", n, m_n);
    }

    const uint8_t* Skip(uint32_t n)
    {
        EnsureHave(n);

        auto pRet = m_p;
        m_p += n;
        m_n -= n;

        return pRet;
    }

    template <typename T>
    const T& Skip_As()
    {
        return *(const T*) Skip(sizeof(T));
    }
};

uint8_t DecodeB64Char(char ch)
{
    if ((ch >= 'A') && (ch <= 'Z'))
        return static_cast<uint8_t>(ch - 'A');

    if ((ch >= 'a') && (ch <= 'z'))
        return static_cast<uint8_t>(26 + ch - 'a');

    if ((ch >= '0') && (ch <= '9'))
        return static_cast<uint8_t>(52 + ch - '0');

    switch (ch)
    {
    case '+':
        return 62;

    case '/':
        return 63;
    }

    return 64; // invalid
}

std::vector<uint8_t> DecodeB64FromCert(const char* sz, uint32_t nLen)
{
    std::vector<uint8_t> vRet;
    uint32_t nPhase = 0;

    for (uint32_t i = 0; i < nLen; i++)
    {
        char ch = sz[i];
        uint8_t val = DecodeB64Char(ch);

        if (val == 64)
        {
            if ('\n' == ch)
                continue;

            if ('=' == ch)
                break;

            ThrowF("invalid b64 char: %c", ch);
        }

        switch (nPhase)
        {
        case 0:
            vRet.push_back(val << 2);
            nPhase = 1;
            break;

        case 1:
            vRet.back() |= (val >> 4);
            vRet.push_back(val << 4);
            nPhase = 2;
            break;

        case 2:
            vRet.back() |= (val >> 2);
            vRet.push_back(val << 6);
            nPhase = 3;
            break;

        case 3:
            vRet.back() |= val;
            nPhase = 0;
        }
    }

    return vRet;
}

MemSlice FindAsn1Value(MemSlice inp, const uint8_t* pOid, uint32_t nOid)
{
    MemSlice ret = { 0, 0 };

    const auto* pBlock = (const uint8_t*) memmem(inp.m_p, inp.m_n, pOid, nOid);
    if (!pBlock)
        return ret;

    inp.Skip((uint32_t) (nOid + (pBlock - inp.m_p)));

    inp.Skip(1); // Tag 0x04

    uint32_t nFieldLen = *inp.Skip(1);

    if (0x80 & nFieldLen)
    {
        auto nLenLen = 0x7f & nFieldLen;
        nFieldLen = 0;

        while (nLenLen--)
        {
            nFieldLen <<= 8;
            nFieldLen |= *inp.Skip(1);
        }
    }

    ret.m_p = inp.Skip(nFieldLen);
    ret.m_n = nFieldLen;

    return ret;

}

void CheckQuote(const uint8_t* pQuote, uint32_t nQuote)
{
    printf("Checking quote...\n");


    uint8_t* pColl = nullptr;
    uint32_t nColl = 0;
    auto qret_coll = tee_qv_get_collateral(pQuote, nQuote, &pColl, &nColl);

    TestRet(sgx_qv_set_enclave_load_policy(sgx_ql_request_policy_t::SGX_QL_PERSISTENT), "sgx_qv_set_enclave_load_policy");

    uint32_t nSuppDataSize = 0;
    TestRet(sgx_qv_get_quote_supplemental_data_size(&nSuppDataSize), "sgx_qv_get_quote_supplemental_data_size");
    std::vector<uint8_t> vSupp(nSuppDataSize);

    auto nTime = time(nullptr);
    uint32_t nCollExpStatus = 1;  // out
    sgx_ql_qv_result_t qvRes = SGX_QL_QV_RESULT_UNSPECIFIED; // out
    TestRet(sgx_qv_verify_quote(
        pQuote, nQuote,
        (const sgx_ql_qve_collateral_t*) pColl,
        nTime,
        &nCollExpStatus,
        &qvRes,
        nullptr,
        nSuppDataSize,
        (vSupp.empty() ? nullptr : vSupp.data())
    ), "sgx_qv_verify_quote");

    TestRet(qret_coll, "tee_qv_get_collateral");

    auto szQvRes = ParseQvRes(qvRes);
    if (szQvRes)
        printf("\tVerification status: %s\n", szQvRes);
    else
        printf("\tVerification status: 0x%08x\n", qvRes);

    if (nCollExpStatus)
        printf("\tWarning: collateral expired\n");

    MemSlice ms;
    ms.m_p = pQuote;
    ms.m_n = nQuote;

    const auto& q = ms.Skip_As<sgx_quote_t>();

    printf("\tversion = %u\n", q.version);
    printf("\tsign_type = %u\n", q.sign_type);

    if (q.version == 3)
    {
        printf("\tepid_group_id = "); PrintHex_T(q.epid_group_id); printf("\n");
        printf("\tqe_svn = %u\n", q.qe_svn);
        printf("\tpce_svn = %u\n", q.pce_svn);
        printf("\txeid = "); PrintHex_T(q.xeid); printf("\n");
        printf("\tbasename = "); PrintHex_T(q.basename); printf("\n");

        const auto& body = q.report_body;
        printf("\treport_body\n");

        printf("\t\tmr_enclave = "); PrintHex_T(body.mr_enclave); printf("\n");
        printf("\t\tmr_signer = "); PrintHex_T(body.mr_signer); printf("\n");
        printf("\t\treport_data = "); PrintHex_T(body.report_data); printf("\n");

        printf("\t\tcpu_svn = "); PrintHex_T(body.cpu_svn); printf("\n");
        printf("\t\tmisc_select = "); PrintHex_T(body.misc_select); printf("\n");
        printf("\t\tisv_ext_prod_id = "); PrintHex_T(body.isv_ext_prod_id); printf("\n");
        printf("\t\tattributes = "); PrintHex_T(body.attributes); printf("\n");
        printf("\t\tconfig_id = "); PrintHex_T(body.config_id); printf("\n");
        printf("\t\tisv_prod_id = %u\n", body.isv_prod_id);
        printf("\t\tisv_svn = %u\n", body.isv_svn);
        printf("\t\tconfig_svn = %u\n", body.config_svn);
        printf("\t\tisv_family_id"); PrintHex_T(body.isv_family_id); printf("\n");
    }

    printf("Analyzing certificate chain...\n");

    /*const auto& ecdsa_sig =*/ ms.Skip_As<sgx_ql_ecdsa_sig_data_t>();

    ms.EnsureHave(q.signature_len - (uint32_t) sizeof(sgx_ql_ecdsa_sig_data_t));
    ms.m_n = q.signature_len;

    const auto& ql_auth = ms.Skip_As<sgx_ql_auth_data_t>();
    ms.Skip(ql_auth.size);

    const auto& ql_cert = ms.Skip_As<sgx_ql_certification_data_t>();
    ms.EnsureHave(ql_cert.size);
    ms.m_n = ql_cert.size;

    static const char szMrk0[] = "-----BEGIN CERTIFICATE-----";
    static const char szMrk1[] = "-----END CERTIFICATE-----";

    auto sz0 = strstr((const char*) ms.m_p, szMrk0);
    auto sz1 = strstr((const char*) ms.m_p, szMrk1);
    if (!(sz0 && sz1) || (sz0 > sz1))
        throw std::runtime_error("can't find leaf certificate");

    auto szCert = sz0 + sizeof(szMrk0) - 1;
    auto nCert = (uint32_t) (sz1 - szCert);
    auto vCert = DecodeB64FromCert(szCert, nCert);
    if (vCert.empty())
        throw std::runtime_error("decoded cert is empty");

    static const uint8_t ppid_oid[] = {
        0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF8, 0x4D, 0x01, 0x0D, 0x01,
    };

    ms.m_p = &vCert.front();
    ms.m_n = (uint32_t) vCert.size();
    ms = FindAsn1Value(ms, ppid_oid, sizeof(ppid_oid));

    if (!ms.m_p)
        throw std::runtime_error("cert has no ppid");

    printf("PPID: ");
    PrintHex(ms.m_p, ms.m_n);
    printf("\n");
    
}

int SGX_CDECL main(int argc, char *argv[])
{
    if (argc != 3)
    {
        printf("USAGE:\n\t%s get <challenge>\n\t%s check <quote>\n", argv[0], argv[0]);
        return 0;
    }

    try
    {
        if (!strcmp(argv[1], "get"))
        {
            auto vQ = GetQuote(argv[2]);
            CheckQuote(&vQ.front(), (uint32_t) vQ.size());
        }
        else
        {
            if (strcmp(argv[1], "check"))
                ThrowF("invalid action: %s", argv[1]);

            auto len = (uint32_t) strlen(argv[2]);
            if (len & 1)
                throw std::runtime_error("quote len must be even");
            len /= 2;

            std::vector<uint8_t> vQ(len);
            ScanHex(&vQ.front(), len, argv[2]);

            CheckQuote(&vQ.front(), len);

        }

    }
    catch(const std::exception& e)
    {
        std::cerr << e.what() << '\n';
    }

    return 0;
}

