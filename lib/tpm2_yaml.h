/* SPDX-License-Identifier: BSD-3-Clause */

#ifndef LIB_TPM2_YAML_H_
#define LIB_TPM2_YAML_H_

#include "tpm2_util.h"

typedef struct tpm2_yaml tpm2_yaml;

tpm2_yaml *tpm2_yaml_new(int canonical);

void tpm2_yaml_free(tpm2_yaml *y);

tool_rc tpm2_yaml_tpm2b_name(const TPM2B_NAME *name, tpm2_yaml *y);

tool_rc tpm2_yaml_hex_string(const char *hex, tpm2_yaml *y);

tool_rc tpm2_yaml_qualified_name(const TPM2B_NAME *qname, tpm2_yaml *y);

tool_rc tpm2_yaml_tpmt_public(tpm2_yaml *y, const TPMT_PUBLIC *public);

tool_rc tpm2_yaml_tpmt_signature_hex(tpm2_yaml *y, const TPMT_PUBLIC *public);

tool_rc tpm2_yaml_named_tpm2b(const char *name, const TPM2B_NAME *tpb2b, tpm2_yaml *y);

tool_rc tpm2_yaml_tpm_alg_todo(tpm2_yaml *y, const TPML_ALG *to_do_list);

tool_rc tpm2_yaml_tpml_alg(tpm2_yaml *y, const TPML_ALG *alg_list);

tool_rc tpm2_yaml_tpm2_nv_index(tpm2_yaml *y, TPM2_NV_INDEX index);

tool_rc tpm2_yaml_nv_read(const char *data, size_t data_len, const TPM2B_NV_PUBLIC *nv_public,
        tpm2_yaml *y);

tool_rc tpm2_yaml_dump(tpm2_yaml *y, FILE *f);

#endif /* LIB_TPM2_YAML_H_ */
