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

#include <sapi/tpm20.h>

#ifndef LIB_TPM2_TCTI_LDR_H_
#define LIB_TPM2_TCTI_LDR_H_

/**
 * Loads a TCTI from a friendly name, library name, or path.
 * For example
 *  friendly:     path = tabrmd
 *  library name: path = libtcti-socket.so
 *  full path:    path = /home/user/lib/libtcti-custom.so
 * @param path
 *  The path/library to load.
 * @param opts
 *  The tcti option configs.
 * @return
 *  A tcti context on success or NULL on failure.
 */
TSS2_TCTI_CONTEXT *tpm2_tcti_ldr_load(const char *path, const char *opts);

/**
 * Returns the loaded TCTIs information structure,
 * which contains the initialization routine, description
 * and help string amongst other things.
 * @return
 *  NULL if no TCTI is loaded, else the info structure pointer.
 */
const TSS2_TCTI_INFO *tpm2_tcti_ldr_getinfo(void);

/**
 * Unloads the tcti loaded via tpm2_tcti_ldr_load();
 */
void tpm2_tcti_ldr_unload(void);

#endif /* LIB_TPM2_TCTI_LDR_H_ */
