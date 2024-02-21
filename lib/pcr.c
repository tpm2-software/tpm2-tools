/* SPDX-License-Identifier: BSD-3-Clause */

#include <inttypes.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "pcr.h"
#include "tpm2.h"
#include "tpm2_systemdeps.h"
#include "tpm2_tool.h"
#include "tpm2_alg_util.h"
#include "tpm2_util.h"

#define MAX(a,b) ((a>b)?a:b)

static inline void set_pcr_select_size(TPMS_PCR_SELECTION *pcr_selection,
        UINT8 size) {

    pcr_selection->sizeofSelect = size;
}

bool pcr_get_id(const char *arg, UINT32 *pcr_id) {

    if (arg == NULL || pcr_id == NULL) {
        LOG_ERR("arg or pcr_id is NULL");
        return false;
    }

    return tpm2_util_handle_from_optarg(arg, pcr_id, TPM2_HANDLE_FLAGS_PCR);
}

static bool pcr_parse_list(const char *str, size_t len,
        TPMS_PCR_SELECTION *pcr_select, tpm2_forward *forward) {
    char buf[4];
    const char *current_string;
    int current_length;
    UINT32 pcr;

    if (str == NULL || len == 0 || strlen(str) == 0) {
        return false;
    }

    pcr_select->sizeofSelect = 3;
    pcr_select->pcrSelect[0] = 0;
    pcr_select->pcrSelect[1] = 0;
    pcr_select->pcrSelect[2] = 0;

    if (!strncmp(str, "all", 3)) {
        pcr_select->pcrSelect[0] = 0xff;
        pcr_select->pcrSelect[1] = 0xff;
        pcr_select->pcrSelect[2] = 0xff;
        return true;
    }

    if (!strncmp(str, "none", 4)) {
        pcr_select->pcrSelect[0] = 0x00;
        pcr_select->pcrSelect[1] = 0x00;
        pcr_select->pcrSelect[2] = 0x00;
        return true;
    }

    do {
        char dgst_buf[sizeof(TPMU_HA) * 2 + 1];
        const char *dgst;;
        int dgst_len = 0;
        UINT16 dgst_size;
        int pcr_len;

        current_string = str;
        str = memchr(current_string, ',', len);
        if (str) {
            current_length = str - current_string;
            str++;
            len -= current_length + 1;
        } else {
            current_length = len;
            len = 0;
        }

        dgst = memchr(current_string, '=', current_length);
        if (dgst && ((str == NULL) || (str && dgst < str))) {
            pcr_len = dgst - current_string;
            dgst++;
            if (str) {
                dgst_len = str - dgst - 1;
            } else {
                dgst_len = current_length - pcr_len - 1;
            }
        } else {
            dgst = NULL;
            pcr_len = current_length;
        }

        if ((size_t) pcr_len > sizeof(buf) - 1) {
            return false;
        }

        snprintf(buf, pcr_len + 1, "%s", current_string);

        if (!pcr_get_id(buf, &pcr)) {
            return false;
        }

        pcr_select->pcrSelect[pcr / 8] |= (1 << (pcr % 8));
        if (dgst && !forward) {
            return false;
        }

        if (dgst) {
            if (strncmp(dgst, "0x", 2) == 0) {
                dgst += 2;
                dgst_len -= 2;
            }

            dgst_size = tpm2_alg_util_get_hash_size(pcr_select->hash);
            if (dgst_size * 2 != dgst_len) {
                return false;
            }

            snprintf(dgst_buf, sizeof(dgst_buf), "%.*s", dgst_len, dgst);
            if (tpm2_util_hex_to_byte_structure(dgst_buf, &dgst_size,
                        (BYTE *)&forward->pcrs[pcr]) != 0) {
                return false;
            }
            forward->pcr_selection.pcrSelect[pcr / 8] |= (1 << (pcr % 8));
        }
    } while (str);

    return true;
}

static bool pcr_parse_selection(const char *str, size_t len,
        TPMS_PCR_SELECTION *pcr_select, tpm2_forward *forward) {
    const char *left_string;
    char buf[9];

    if (str == NULL || len == 0 || strlen(str) == 0)
        return false;

    left_string = memchr(str, ':', len);

    if (left_string == NULL) {
        return false;
    }

    if ((size_t) (left_string - str) > sizeof(buf) - 1) {
        return false;
    }

    snprintf(buf, left_string - str + 1, "%s", str);

    pcr_select->hash = tpm2_alg_util_from_optarg(buf, tpm2_alg_util_flags_hash);

    if (pcr_select->hash == TPM2_ALG_ERROR) {
        return false;
    }

    if (forward) {
        forward->pcr_selection.hash = pcr_select->hash;
    }

    left_string++;

    if ((size_t) (left_string - str) >= len) {
        return false;
    }

    if (!pcr_parse_list(left_string, str + len - left_string, pcr_select,
            forward)) {
        return false;
    }

    return true;
}

static void shrink_pcr_selection(TPML_PCR_SELECTION *s) {

    UINT32 i, j;

    //seek for the first empty item
    for (i = 0; i < s->count; i++)
        if (!s->pcrSelections[i].hash)
            break;
    j = i + 1;

    for (; i < s->count; i++) {
        if (!s->pcrSelections[i].hash) {
            for (; j < s->count; j++)
                if (s->pcrSelections[j].hash)
                    break;
            if (j >= s->count)
                break;

            memcpy(&s->pcrSelections[i], &s->pcrSelections[j],
                    sizeof(s->pcrSelections[i]));
            s->pcrSelections[j].hash = 0;
            j++;
        }
    }

    s->count = i;
}

static void pcr_update_pcr_selections(TPML_PCR_SELECTION *s1,
        TPML_PCR_SELECTION *s2) {
    UINT32 i1, i2, j;
    for (i2 = 0; i2 < s2->count; i2++) {
        for (i1 = 0; i1 < s1->count; i1++) {
            if (s2->pcrSelections[i2].hash != s1->pcrSelections[i1].hash)
                continue;

            for (j = 0; j < s1->pcrSelections[i1].sizeofSelect; j++)
                s1->pcrSelections[i1].pcrSelect[j] &=
                        ~s2->pcrSelections[i2].pcrSelect[j];
        }
    }
}

static bool pcr_unset_pcr_sections(TPML_PCR_SELECTION *s) {
    UINT32 i, j;
    for (i = 0; i < s->count; i++) {
        for (j = 0; j < s->pcrSelections[i].sizeofSelect; j++) {
            if (s->pcrSelections[i].pcrSelect[j]) {
                return false;
            }
        }
    }

    return true;
}

bool pcr_print_pcr_struct_le(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs) {

    UINT32 vi = 0, di = 0, i;
    bool result = true;

    tpm2_tool_output("pcrs:\n");

    /* Loop through all PCR/hash banks */
    for (i = 0; i < le32toh(pcr_select->count); i++) {
        const char *alg_name = tpm2_alg_util_algtostr(
                le16toh(pcr_select->pcrSelections[i].hash), tpm2_alg_util_flags_hash);

        tpm2_tool_output("  %s:\n", alg_name);

        /* Loop through all PCRs in this bank */
        unsigned int pcr_id;
        for (pcr_id = 0; pcr_id < pcr_select->pcrSelections[i].sizeofSelect * 8u;
                pcr_id++) {
            if (!tpm2_util_is_pcr_select_bit_set(&pcr_select->pcrSelections[i],
                    pcr_id)) {
                continue; // skip non-selected banks
            }
            if (vi >= le64toh(pcrs->count) || di >= le32toh(pcrs->pcr_values[vi].count)) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            /* Print out PCR ID */
            tpm2_tool_output("    %-2d: 0x", pcr_id);

            /* Print out current PCR digest value */
            TPM2B_DIGEST *b = &pcrs->pcr_values[vi].digests[di];
            int k;
            for (k = 0; k < le16toh(b->size); k++) {
                tpm2_tool_output("%02X", b->buffer[k]);
            }
            tpm2_tool_output("\n");

            if (++di < le32toh(pcrs->pcr_values[vi].count)) {
                continue;
            }

            di = 0;
            if (++vi < le64toh(pcrs->count)) {
                continue;
            }
        }
    }

    return result;
}

bool pcr_fwrite_serialized(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *ppcrs, FILE *output_file) {

    TPML_PCR_SELECTION pcr_selection = *pcr_select;
    for (UINT32 i = 0; i < pcr_selection.count; i++) {
        TPMS_PCR_SELECTION *p = &pcr_selection.pcrSelections[i];
        p->hash = htole16(p->hash);
    }
    pcr_selection.count = htole32(pcr_selection.count);

    // Export TPML_PCR_SELECTION structure to pcr outfile
    size_t fwrite_len = fwrite(&pcr_selection, sizeof(TPML_PCR_SELECTION),
        1, output_file);
    if (fwrite_len != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    // Export PCR digests to pcr outfile
    UINT32 count = htole32(ppcrs->count);
    fwrite_len = fwrite(&count, sizeof(UINT32), 1, output_file);
    if (fwrite_len != 1) {
        LOG_ERR("write to output file failed: %s", strerror(errno));
        return false;
    }

    tpm2_pcrs pcrs = *ppcrs;
    for (size_t j = 0; j < pcrs.count; j++) {
        TPML_DIGEST *pcr_value = &pcrs.pcr_values[j];

        for (size_t k = 0; k < pcr_value->count; k++) {
            TPM2B_DIGEST *p = &pcr_value->digests[k];
            p->size = htole16(p->size);
        }
        pcr_value->count = htole32(pcr_value->count);
        fwrite_len = fwrite(pcr_value, sizeof(TPML_DIGEST), 1, output_file);
        if (fwrite_len != 1) {
            LOG_ERR("write to output file failed: %s", strerror(errno));
            return false;
        }
    }

    return true;
}

bool pcr_fwrite_values(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *pcrs, FILE *output_file) {

    size_t vi = 0;  /* value index */
    UINT32 di = 0;  /* digest index */
    // Loop through all PCR/hash banks
    for (UINT32 i = 0; i < pcr_select->count; i++) {
        const TPMS_PCR_SELECTION *pcr_selection = &pcr_select->pcrSelections[i];
        // Loop through all PCRs in this bank
        for (unsigned int pcr_id = 0; pcr_id < pcr_selection->sizeofSelect * 8u;
            pcr_id++) {

            bool is_pcr_select_bit_set = tpm2_util_is_pcr_select_bit_set(
                pcr_selection, pcr_id);
            if (! is_pcr_select_bit_set) {
                // skip non-selected banks
                continue;
            }
            const TPML_DIGEST *pcr_value = &pcrs->pcr_values[vi];
            if (vi >= pcrs->count || di >= pcr_value->count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            // Print out current PCR digest value
            const TPM2B_DIGEST *digest = &pcr_value->digests[di];
            size_t fwrite_len = fwrite(digest->buffer, digest->size, 1,
                output_file);
            if (fwrite_len != 1) {
                LOG_ERR("write to output file failed: %s", strerror(errno));
                return false;
            }

            if (++di >= pcr_value->count) {
                di = 0;
                ++vi;
            }
        } /* end looping through all PCRs in a bank */
    }  /* end looping through all PCR banks */

    return true;
}

bool pcr_print_values(const TPML_PCR_SELECTION *pcr_select,
    const tpm2_pcrs *pcrs) {

    size_t vi = 0;  /* value index */
    UINT32 di = 0;  /* digest index */
    // Loop through all PCR/hash banks
    for (UINT32 i = 0; i < pcr_select->count; i++) {
        const TPMS_PCR_SELECTION *pcr_selection = &pcr_select->pcrSelections[i];
        const char *alg_name = tpm2_alg_util_algtostr(pcr_selection->hash,
            tpm2_alg_util_flags_hash);

        tpm2_tool_output("  %s:\n", alg_name);

        // Loop through all PCRs in this bank
        for (unsigned int pcr_id = 0; pcr_id < pcr_selection->sizeofSelect * 8u;
            pcr_id++) {

            bool is_pcr_select_bit_set = tpm2_util_is_pcr_select_bit_set(
                pcr_selection, pcr_id);
            if (! is_pcr_select_bit_set) {
                // skip non-selected banks
                continue;
            }
            const TPML_DIGEST *pcr_value = &pcrs->pcr_values[vi];
            if (vi >= pcrs->count || di >= pcr_value->count) {
                LOG_ERR("Something wrong, trying to print but nothing more");
                return false;
            }

            // Print out PCR ID
            tpm2_tool_output("    %-2d: 0x", pcr_id);

            // Print out current PCR digest value
            const TPM2B_DIGEST *digest = &pcr_value->digests[di];
            for (int k = 0; k < digest->size; k++) {
                tpm2_tool_output("%02X", digest->buffer[k]);
            }
            tpm2_tool_output("\n");

            if (++di >= pcr_value->count) {
                di = 0;
                ++vi;
            }
        } /* end looping through all PCRs in a bank */
    }  /* end looping through all PCR banks */

    return true;
}

bool pcr_print_pcr_struct(TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs) {
    tpm2_tool_output("pcrs:\n");
    return pcr_print_values(pcr_select, pcrs);
}

bool pcr_print_pcr_selections(TPML_PCR_SELECTION *pcr_selections) {
    tpm2_tool_output("selected-pcrs:\n");

    /* Iterate throught the pcr banks */
    UINT32 i;
    for (i = 0; i < pcr_selections->count; i++) {
        /* Print hash alg of the current bank */
        const char *halgstr = tpm2_alg_util_algtostr(
                pcr_selections->pcrSelections[i].hash,
                tpm2_alg_util_flags_hash);
        if (halgstr != NULL) {
            tpm2_tool_output("  - %s: [", halgstr);
        } else {
            LOG_ERR("Unsupported hash algorithm 0x%08x",
                    pcr_selections->pcrSelections[i].hash);
            return false;
        }

        /* Iterate through the PCRs of the bank */
        bool first = true;
        unsigned j;
        for (j = 0; j < pcr_selections->pcrSelections[i].sizeofSelect * 8;
                j++) {
            if ((pcr_selections->pcrSelections[i].pcrSelect[j / 8]
                    & 1 << (j % 8)) != 0) {
                if (first) {
                    tpm2_tool_output(" %i", j);
                    first = false;
                } else {
                    tpm2_tool_output(", %i", j);
                }
            }
        }
        tpm2_tool_output(" ]\n");
    }

    return true;
}

bool pcr_parse_selections(const char *arg, TPML_PCR_SELECTION *pcr_select,
        tpm2_forwards *forwards) {
    const char *left_string = arg;
    const char *current_string = arg;
    int current_length = 0;

    if (arg == NULL || pcr_select == NULL) {
        return false;
    }

    pcr_select->count = 0;
    if (forwards) {
        forwards->count = 0;
    }

    do {
        current_string = left_string;

        left_string = strchr(current_string, '+');
        if (left_string) {
            current_length = left_string - current_string;
            left_string++;
        } else
            current_length = strlen(current_string);

        if (!pcr_parse_selection(current_string, current_length,
                &pcr_select->pcrSelections[pcr_select->count],
                forwards ? &forwards->bank[forwards->count] : NULL))
            return false;

        pcr_select->count++;
        if (forwards) {
            forwards->count++;
        }
    } while (left_string);

    if (pcr_select->count == 0) {
        return false;
    }
    return true;
}

tool_rc pcr_get_banks(ESYS_CONTEXT *esys_context,
        TPMS_CAPABILITY_DATA *capability_data, tpm2_algorithm *algs) {

    TPMI_YES_NO more_data;
    TPMS_CAPABILITY_DATA *capdata_ret;

    tool_rc rc = tpm2_get_capability(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
            ESYS_TR_NONE, TPM2_CAP_PCRS, no_argument, required_argument,
            &more_data, &capdata_ret);
    if (rc != tool_rc_success) {
        return rc;
    }

    *capability_data = *capdata_ret;

    unsigned i;

    // If the TPM support more bank algorithm that we currently
    // able to manage, throw an error
    if (capability_data->data.assignedPCR.count > ARRAY_LEN(algs->alg)) {
        LOG_ERR("Current implementation does not support more than %zu banks, "
                "got %" PRIu32 " banks supported by TPM",
                sizeof(algs->alg), capability_data->data.assignedPCR.count);
        free(capdata_ret);
        return tool_rc_general_error;
    }

    for (i = 0; i < capability_data->data.assignedPCR.count; i++) {
        algs->alg[i] = capability_data->data.assignedPCR.pcrSelections[i].hash;
    }
    algs->count = capability_data->data.assignedPCR.count;

    free(capdata_ret);
    return tool_rc_success;
}

bool pcr_init_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_sel, TPMI_ALG_HASH alg_id) {

    UINT32 i, j;

    pcr_sel->count = 0;

    for (i = 0; i < cap_data->data.assignedPCR.count; i++) {
        if (alg_id
                && (cap_data->data.assignedPCR.pcrSelections[i].hash != alg_id))
            continue;
        pcr_sel->pcrSelections[pcr_sel->count].hash =
                cap_data->data.assignedPCR.pcrSelections[i].hash;
        set_pcr_select_size(&pcr_sel->pcrSelections[pcr_sel->count],
                cap_data->data.assignedPCR.pcrSelections[i].sizeofSelect);
        for (j = 0; j < pcr_sel->pcrSelections[pcr_sel->count].sizeofSelect;
                j++)
            pcr_sel->pcrSelections[pcr_sel->count].pcrSelect[j] =
                    cap_data->data.assignedPCR.pcrSelections[i].pcrSelect[j];
        pcr_sel->count++;
    }

    if (pcr_sel->count == 0)
        return false;

    return true;
}

bool pcr_check_pcr_selection(TPMS_CAPABILITY_DATA *cap_data,
        TPML_PCR_SELECTION *pcr_sel) {

    UINT32 i, j, k;

    for (i = 0; i < pcr_sel->count; i++) {
        for (j = 0; j < cap_data->data.assignedPCR.count; j++) {
            if (pcr_sel->pcrSelections[i].hash
                    == cap_data->data.assignedPCR.pcrSelections[j].hash) {
                for (k = 0; k < pcr_sel->pcrSelections[i].sizeofSelect; k++)
                    pcr_sel->pcrSelections[i].pcrSelect[k] &=
                            cap_data->data.assignedPCR.pcrSelections[j].pcrSelect[k];
                break;
            }
        }

        if (j >= cap_data->data.assignedPCR.count) {
            const char *alg_name = tpm2_alg_util_algtostr(
                    pcr_sel->pcrSelections[i].hash, tpm2_alg_util_flags_hash);
            LOG_WARN("Ignore unsupported bank/algorithm: %s(0x%04x)", alg_name,
                    pcr_sel->pcrSelections[i].hash);
            pcr_sel->pcrSelections[i].hash = 0; //mark it as to be removed
        }
    }

    shrink_pcr_selection(pcr_sel);
    if (pcr_sel->count == 0)
        return false;

    return true;
}

tool_rc pcr_read_pcr_values(ESYS_CONTEXT *esys_context,
        TPML_PCR_SELECTION *pcr_select, tpm2_pcrs *pcrs, TPM2B_DIGEST *cp_hash,
        TPMI_ALG_HASH parameter_hash_algorithm) {

    TPML_PCR_SELECTION pcr_selection_tmp;
    TPML_PCR_SELECTION *pcr_selection_out;
    UINT32 pcr_update_counter;

    //1. prepare pcrSelectionIn with g_pcrSelections
    memcpy(&pcr_selection_tmp, pcr_select, sizeof(pcr_selection_tmp));

    //2. call pcr_read
    pcrs->count = 0;
    do {
        TPML_DIGEST *v;
        tool_rc rc = tpm2_pcr_read(esys_context, ESYS_TR_NONE, ESYS_TR_NONE,
                ESYS_TR_NONE, &pcr_selection_tmp, &pcr_update_counter,
                &pcr_selection_out, &v, cp_hash, parameter_hash_algorithm);

        if (rc != tool_rc_success || (cp_hash && cp_hash->size)) {
            return rc;
        }

        pcrs->pcr_values[pcrs->count] = *v;

        free(v);

        //3. unmask pcrSelectionOut bits from pcrSelectionIn
        pcr_update_pcr_selections(&pcr_selection_tmp, pcr_selection_out);

        free(pcr_selection_out);

        //4. goto step 2 if pcrSelctionIn still has bits set
    } while (++pcrs->count < ARRAY_LEN(pcrs->pcr_values)
            && !pcr_unset_pcr_sections(&pcr_selection_tmp));

    if (pcrs->count >= ARRAY_LEN(pcrs->pcr_values)
            && !pcr_unset_pcr_sections(&pcr_selection_tmp)) {
        LOG_ERR("too much pcrs to get! try to split into multiple calls...");
        return tool_rc_general_error;
    }

    return tool_rc_success;
}
