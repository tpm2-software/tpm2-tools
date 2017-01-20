#ifndef SRC_PCR_H_
#define SRC_PCR_H_

#include <sapi/tpm20.h>

int pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcrSels);
int pcr_parse_list(const char *str, int len, TPMS_PCR_SELECTION *pcrSel);

#endif /* SRC_PCR_H_ */
