/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_H_
#define LIB_TPM2_H_

#include <tss2/tss2_esys.h>

#include "tpm2_tool.h"

tool_rc tpm2_from_tpm_public(
            ESYS_CONTEXT *esysContext,
            TPM2_HANDLE tpm_handle,
            ESYS_TR optionalSession1,
            ESYS_TR optionalSession2,
            ESYS_TR optionalSession3,
            ESYS_TR *object);

tool_rc tpm2_close(
        ESYS_CONTEXT *esys_context,
        ESYS_TR *rsrc_handle);

tool_rc tpm2_nv_readpublic(
        ESYS_CONTEXT *esysContext,
        ESYS_TR nvIndex,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_NV_PUBLIC **nvPublic,
        TPM2B_NAME **nvName);

tool_rc tpm2_readpublic(ESYS_CONTEXT *esysContext,
        ESYS_TR objectHandle,
        ESYS_TR shandle1,
        ESYS_TR shandle2,
        ESYS_TR shandle3,
        TPM2B_PUBLIC **outPublic,
        TPM2B_NAME **name,
        TPM2B_NAME **qualifiedName);

#endif /* LIB_TPM2_H_ */
