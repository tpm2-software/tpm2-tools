/* SPDX-License-Identifier: BSD-3-Clause */
//**********************************************************************;
// Copyright (c) 2018, Intel Corporation
// All rights reserved.
//
//**********************************************************************;

#include <tss2/tss2_sys.h>

#ifndef LIB_TPM2_TCTI_LDR_H_
#define LIB_TPM2_TCTI_LDR_H_

/**
 * Loads a TCTI from a friendly name, library name, or path.
 * For example
 *  friendly:     path = tabrmd
 *  library name: path = libtss2-tcti-mssim.so
 *  full path:    path = /home/user/lib/libtss2-tcti-custom.so
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
 * Given a tcti name, like mssim, tells you if the
 * library is present using dlopen(3).
 * @param name
 *   The friendly name of the tcti.
 * @return
 *  True if present, false otherwise.
 */
bool tpm2_tcti_ldr_is_tcti_present(const char *name);

/**
 * Unloads the tcti loaded via tpm2_tcti_ldr_load();
 */
void tpm2_tcti_ldr_unload(void);

#endif /* LIB_TPM2_TCTI_LDR_H_ */
