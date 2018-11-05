#include "tpm2_alg_util.h"
#include "tpm2_util.h"

#define SESSION_HANDLE 0xBADC0DE

typedef struct expected_data expected_data;
struct expected_data {
    struct {
        ESYS_TR key;
        ESYS_TR bind;
        TPM2_SE session_type;
        TPMT_SYM_DEF symmetric;
        TPMI_ALG_HASH auth_hash;
        TPM2B_NONCE nonce_caller;
    } input;

    struct output {
        ESYS_TR handle;
        TPM2_RC rc;
    } output;
};

static inline void set_expected(ESYS_TR key, ESYS_TR bind,
        TPM2_SE session_type,
        TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH auth_hash,
        TPM2B_NONCE *nonce_caller, ESYS_TR handle, TPM2_RC rc) {

    expected_data *e = calloc(1, sizeof(*e));
    assert_non_null(e);

    e->input.key = key;
    e->input.bind = bind;
    e->input.session_type = session_type;
    e->input.symmetric = *symmetric;
    e->input.auth_hash = auth_hash;
    e->input.nonce_caller = *nonce_caller;

    e->output.handle = handle;
    e->output.rc = rc;

    will_return(__wrap_Esys_StartAuthSession, e);
}

static inline void set_expected_defaults(TPM2_SE session_type,
        ESYS_TR handle, TPM2_RC rc) {

    TPMT_SYM_DEF symmetric;
    memset(&symmetric, 0, sizeof(symmetric));
    symmetric.algorithm = TPM2_ALG_NULL;

    TPM2B_NONCE nonce_caller;
    memset(&nonce_caller, 0, sizeof(nonce_caller));
    nonce_caller.size = tpm2_alg_util_get_hash_size(TPM2_ALG_SHA1);

    set_expected(
    ESYS_TR_NONE,
    ESYS_TR_NONE, session_type, &symmetric,
    TPM2_ALG_SHA256, &nonce_caller, handle, rc);
}

TSS2_RC __wrap_Esys_StartAuthSession(ESYS_CONTEXT *esysContext,
            ESYS_TR tpmKey, ESYS_TR bind,
            ESYS_TR shandle1, ESYS_TR shandle2, ESYS_TR shandle3,
            const TPM2B_NONCE *nonceCaller, TPM2_SE sessionType,
            const TPMT_SYM_DEF *symmetric, TPMI_ALG_HASH authHash,
            ESYS_TR *sessionHandle) {

    UNUSED(esysContext);
    UNUSED(shandle1);
    UNUSED(shandle2);
    UNUSED(shandle3);
    UNUSED(sessionHandle);

    expected_data *e = mock_ptr_type(expected_data *);

    assert_int_equal(tpmKey, e->input.key);

    assert_int_equal(bind, e->input.bind);

    assert_memory_equal(nonceCaller, &e->input.nonce_caller,
            sizeof(*nonceCaller));

    assert_int_equal(sessionType, e->input.session_type);

    assert_memory_equal(symmetric, &e->input.symmetric,
            sizeof(*symmetric));

    assert_int_equal(authHash, e->input.auth_hash);

    *sessionHandle = e->output.handle;

    TSS2_RC rc = e->output.rc;
    free(e);
    return rc;
}
