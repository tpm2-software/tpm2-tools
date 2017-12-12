/*
 * Copyright (c) 2017, Eho.Link
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
#include <stdbool.h>
#include <stdlib.h>

#include "log.h"
#include "tpm2_tool.h"
#include "tpm2_util.h"
#include "tpm2_password_util.h"

int tpm2_tool_onrun(TSS2_SYS_CONTEXT *sapi_context, tpm2_option_flags flags)
{
	UNUSED(flags);

	LOG_INFO ("Sending TPM2_Clear command");

	TSS2L_SYS_AUTH_RESPONSE sessionsDataOut;
	TSS2L_SYS_AUTH_COMMAND sessionsData = {
		.count = 1,
		.auths = {
			TPMS_AUTH_COMMAND_INIT(TPM2_RS_PW),
		}
	};

	TSS2_RC rc = TSS2_RETRY_EXP(Tss2_Sys_Clear (sapi_context,
					    TPM2_RH_PLATFORM,
					    &sessionsData,
					    &sessionsDataOut));

	if (rc != TPM2_RC_SUCCESS && rc != TPM2_RC_INITIALIZE) {
		LOG_ERR ("Tss2_Sys_Clear failed: 0x%x",
			 rc);
		return 1;
	}

	LOG_INFO ("Success. TSS2_RC: 0x%x", rc);
	return 0;
}
