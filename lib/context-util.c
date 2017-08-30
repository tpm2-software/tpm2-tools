/*
 * Copyright (c) 2016, Intel Corporation
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 * this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of Intel Corporation nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
 * THE POSSIBILITY OF SUCH DAMAGE.
 */
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#ifdef HAVE_TCTI_DEV
#endif
#ifdef HAVE_TCTI_SOCK
#endif
#ifdef HAVE_TCTI_TABRMD
#include <tcti/tcti-tabrmd.h>
#endif

#include "context-util.h"
#include "log.h"

/*
 * Initialize a socket TCTI instance using the provided options structure.
 * The address and port are the only configuration options used. Callbacks
 * for logging are set to NULL.
 * The caller is returned a TCTI context structure that is allocated by this
 * function. This structure must be freed by the caller.
 */
#ifdef HAVE_TCTI_SOCK

#endif
#ifdef HAVE_TCTI_TABRMD

#endif

/*
 * Teardown the provided TCTI context. This includes finalizing the
 * context and freeing the data for the context.
 */
void
tcti_teardown (TSS2_TCTI_CONTEXT *tcti_context)
{
    if (tcti_context == NULL)
        return;
    tss2_tcti_finalize (tcti_context);
    free (tcti_context);
}
/*
 * Teardown the provided SAPI context. This includes finalizing the
 * context and freeing the data for the context.
 */
void
sapi_teardown (TSS2_SYS_CONTEXT *sapi_context)
{
    if (sapi_context == NULL)
        return;
    Tss2_Sys_Finalize (sapi_context);
    free (sapi_context);
}
/*
 * Teardown and free the resoruces associted with a SAPI context structure.
 * This includes tearing down the TCTI as well.
 */
void
sapi_teardown_full (TSS2_SYS_CONTEXT *sapi_context)
{
    TSS2_TCTI_CONTEXT *tcti_context = NULL;
    TSS2_RC rc;

    rc = Tss2_Sys_GetTctiContext (sapi_context, &tcti_context);
    if (rc != TSS2_RC_SUCCESS)
        return;
    sapi_teardown (sapi_context);
    tcti_teardown (tcti_context);
}
