//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
// this list of conditions and the following disclaimer.
//
// 2. Redistributions in binary form must reproduce the above copyright notice,
// this list of conditions and the following disclaimer in the documentation
// and/or other materials provided with the distribution.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF
// THE POSSIBILITY OF SUCH DAMAGE.
//**********************************************************************;
#ifndef TPM2_HMAC_AUTH_H_
#define TPM2_HMAC_AUTH_H_

#include "tpm2_session.h"

/**
 * Calculates HMAC of the command parameters used in HMAC authentication
 *
 * @param sapi_context
 *  The sapi context
 * @param[in] auth_handle
 *  The handle whose authentication value is intended for authorization of command
 * @param hmac_session
 *  The hmac authentication session in to which the command is authorized
 * @param session_data
 *  The session data
 * @param[in] entity_1_name
 *  Name of the first entity in the command parameters
 * @param[in] entity_2_name
 * Name of the first entity in the command parameters
 * @return
 *   True on success, false otherwise.
 */
bool tpm2_hmac_auth_get_command_buffer_hmac(TSS2_SYS_CONTEXT *sapi_context,
	TPM2_HANDLE auth_handle, tpm2_session *hmac_session,
	TPMS_AUTH_COMMAND *session_data, TPM2B_NAME entity_1_name,
	TPM2B_NAME entity_2_name);

/**
 * Calculates and retrieves the name of entity depending on the entity type
 *
 * @param sapi_context
 *  The sapi context
 * @param[in] entity_handle
 *  The entity's handle
 * @param  entity_name
 *  The calculated entity's name
 * @return
 *  True on success, false otherwise.
 */
bool tpm2_hmac_auth_get_entity_name(TSS2_SYS_CONTEXT *sapi_context, TPM2_HANDLE entity_handle,
	TPM2B_NAME *entity_name);

#endif /* TPM2_HMAC_AUTH_H_ */
