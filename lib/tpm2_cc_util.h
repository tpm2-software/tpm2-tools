/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_CC_UTIL_H_
#define LIB_TPM2_CC_UTIL_H_

#include <stdbool.h>

#include <tss2/tss2_tpm2_types.h>

bool tpm2_cc_util_from_str(const char *str, TPM2_CC *cc);

#endif /* LIB_TPM2_CC_UTIL_H_ */
