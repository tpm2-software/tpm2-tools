#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <stdbool.h>

#include <sapi/tpm20.h>

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
bool pcr_parse_list(const char *str, size_t len, TPMS_PCR_SELECTION *pcrSel);
TPM_RC get_max_supported_pcrs(TSS2_SYS_CONTEXT *sapi_context, UINT32 *max_pcrs);

#endif /* SRC_PCR_H_ */
