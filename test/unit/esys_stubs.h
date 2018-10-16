/*
 * Various helper functions copy/pasted from tpm2-tss to help mock ESAPI
 * interfaces such that we can unit test our code.
 */
#ifndef ESYS_STUBS_H
#define ESYS_STUBS_H

#include <string.h>

#include <tss2/tss2_esys.h>

#define TCTI_FAKE_MAGIC 0x46414b4500000000ULL        /* 'FAKE\0' */
#define TCTI_FAKE_VERSION 0x1

typedef struct {
    uint64_t magic;
    uint32_t version;
    TSS2_TCTI_TRANSMIT_FCN transmit;
    TSS2_TCTI_RECEIVE_FCN receive;
    TSS2_RC(*finalize) (TSS2_TCTI_CONTEXT * tctiContext);
    TSS2_RC(*cancel) (TSS2_TCTI_CONTEXT * tctiContext);
    TSS2_RC(*getPollHandles) (TSS2_TCTI_CONTEXT * tctiContext,
                           TSS2_TCTI_POLL_HANDLE * handles,
                           size_t * num_handles);
    TSS2_RC(*setLocality) (TSS2_TCTI_CONTEXT * tctiContext, uint8_t locality);
} TSS2_TCTI_CONTEXT_FAKE;

TSS2_TCTI_POLL_HANDLE rev[] = {
    {.fd=66, .events=1, .revents=0},
    {.fd=99, .events=1, .revents=0}
};

static TSS2_RC
tcti_fake_getpollhandles(TSS2_TCTI_CONTEXT * tctiContext,
                         TSS2_TCTI_POLL_HANDLE * handles,
                         size_t * num_handles)
{
    (void) tctiContext;
    if (handles == NULL) {
        *num_handles = 2;
        return TSS2_RC_SUCCESS;
    }
    assert_int_equal(*num_handles, 2);
    memcpy(&handles[0], &rev[0], sizeof(rev));
    return TSS2_RC_SUCCESS;
}

static TSS2_RC
tcti_fake_initialize(TSS2_TCTI_CONTEXT * tctiContext, size_t * contextSize)
{
    TSS2_TCTI_CONTEXT_FAKE *tcti_fake =
        (TSS2_TCTI_CONTEXT_FAKE *) tctiContext;

    if (tctiContext == NULL && contextSize == NULL) {
        return TSS2_TCTI_RC_BAD_VALUE;
    } else if (tctiContext == NULL) {
        *contextSize = sizeof(*tcti_fake);
        return TSS2_RC_SUCCESS;
    }

    /* Init TCTI context */
    memset(tcti_fake, 0, sizeof(*tcti_fake));
    TSS2_TCTI_MAGIC(tctiContext) = TCTI_FAKE_MAGIC;
    TSS2_TCTI_VERSION(tctiContext) = TCTI_FAKE_VERSION;
    TSS2_TCTI_TRANSMIT(tctiContext) = (void*)1;
    TSS2_TCTI_RECEIVE(tctiContext) = (void*)1;
    TSS2_TCTI_FINALIZE(tctiContext) = NULL;
    TSS2_TCTI_CANCEL(tctiContext) = NULL;
    TSS2_TCTI_GET_POLL_HANDLES(tctiContext) = tcti_fake_getpollhandles;
    TSS2_TCTI_SET_LOCALITY(tctiContext) = NULL;

    return TSS2_RC_SUCCESS;
}

#endif /* ESYS_STUBS_H */
