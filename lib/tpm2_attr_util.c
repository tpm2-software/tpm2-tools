/* SPDX-License-Identifier: BSD-3-Clause */

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "log.h"
#include "tpm2_attr_util.h"

typedef struct _attrstrmap {
    UINT32 mask;
    UINT32 value;
    char *name[6];
} attrstrmap;

static bool attrstrmap_string_to_attr(const attrstrmap *map, size_t map_size, char *str, UINT32 *attr) {
    char *token;
    char *save = NULL;
    bool tpm_nt_ordinary = false;

    if (!str || !attr) {
        LOG_ERR("attribute list or attributes structure is NULL");
        return false;
    }

    *attr = 0;

    /* Unfortunately the value for TPM2_NT_ORDINARY is zero.
       As such we cannot just check if the masked out *attr value is non-zero below
       for conflict detection, but we have to do some special handling. */
    if (strcasestr(str, "ordinary")) {
        tpm_nt_ordinary = true;
    }

    for (token = strtok_r(str, "|", &save); token != NULL;
         token = strtok_r(NULL, "|", &save)) {
        bool matched = false;;
        for (size_t i = 0; i < map_size; i++) {
            for (size_t j = 0; j < ARRAY_LEN(map[i].name); j++) {
                if (!map[i].name[j])
                    continue;
                if (map[i].name[j] && strcasecmp(token, map[i].name[j]) == 0) {
                    if (*attr & map[i].mask) {
                        LOG_ERR("Attribute conflict for token: \"%s\"", token);
                        return false;
                    }
                    *attr |= map[i].value;
                    matched = true;
                    break;
                }
            }
        }
        if (!matched) {
            LOG_ERR("Unknown attribute token: \"%s\"", token);
            return false;
        }
    }

    /* This is the special handling */
    if (tpm_nt_ordinary && !(*attr & (0xf << 4))) {
        LOG_ERR("Attribute conflict for token: \"ordinary\" found.");
        return false;
    }

    return true;
}

static char *attrstrmap_attr_to_string(const attrstrmap *map, size_t map_size, UINT32 value) {
    char *ret = calloc(1,1);
    char *retold = NULL;
    if (!ret) {
        LOG_ERR("Failed to allocate memory");
        return NULL;
    }
    for (size_t i = 0; i < map_size; i++) {
        if ((value & map[i].mask) == map[i].value) {
            if (!map[i].name[0])
                continue;
            retold = ret;
            ret = realloc(ret, strlen(ret) + strlen(map[i].name[0]) + 2);
            if (!ret) {
                LOG_ERR("Failed to allocate memory");
                free(retold);
                return NULL;
            }
            strcat(ret, map[i].name[0]);
            strcat(ret, "|");
            value &= ~map[i].mask;
        }
    }
    if (value != 0) {
        LOG_ERR("Unknown attribute bits set: 0x%x", value);
        free(ret);
        return NULL;
    }
    ret[strlen(ret) - 1] = '\0';
    return ret;
}

static const attrstrmap nv_attr_map[] = {
    { .mask = (1 << 0), .value = TPMA_NV_PPWRITE, .name = { "ppwrite", } },
    { .mask = (1 << 1), .value = TPMA_NV_OWNERWRITE, .name = { "ownerwrite", } },
    { .mask = (1 << 2), .value = TPMA_NV_AUTHWRITE, .name = { "authwrite", } },
    { .mask = (1 << 3), .value = TPMA_NV_POLICYWRITE, .name = { "policywrite", } },
    { .mask = (0xf << 4), .value = (TPM2_NT_ORDINARY << TPMA_NV_TPM2_NT_SHIFT), .name = { NULL, "ordinary", "nt=ordinary", "nt=0x00", "nt=0x0", "nt=0" } },
    { .mask = (0xf << 4), .value = (TPM2_NT_COUNTER << TPMA_NV_TPM2_NT_SHIFT), .name = { "counter", "nt=counter", "nt=0x01", "nt=0x1", "nt=1" } },
    { .mask = (0xf << 4), .value = (TPM2_NT_BITS << TPMA_NV_TPM2_NT_SHIFT), .name = { "bits", "nt=bits", "nt=0x02", "nt=0x2", "nt=2" } },
    { .mask = (0xf << 4), .value = (TPM2_NT_EXTEND << TPMA_NV_TPM2_NT_SHIFT), .name = { "extend", "nt=extend", "nt=0x04", "nt=0x4", "nt=4" } },
    { .mask = (0xf << 4), .value = (TPM2_NT_PIN_FAIL << TPMA_NV_TPM2_NT_SHIFT), .name = { "pinfail", "nt=pinfail", "nt=0x08", "nt=0x8", "nt=8" } },
    { .mask = (0xf << 4), .value = (TPM2_NT_PIN_PASS << TPMA_NV_TPM2_NT_SHIFT), .name = { "pinpass", "nt=pinpass", "nt=0x09", "nt=0x9", "nt=9" } },
    { .mask = (1 << 10), .value = TPMA_NV_POLICY_DELETE, .name = { "policydelete", } },
    { .mask = (1 << 11), .value = TPMA_NV_WRITELOCKED, .name = { "writelocked", } },
    { .mask = (1 << 12), .value = TPMA_NV_WRITEALL, .name = { "writeall", } },
    { .mask = (1 << 13), .value = TPMA_NV_WRITEDEFINE, .name = { "writedefine", } },
    { .mask = (1 << 14), .value = TPMA_NV_WRITE_STCLEAR, .name = { "write_stclear", } },
    { .mask = (1 << 15), .value = TPMA_NV_GLOBALLOCK, .name = { "globallock", } },
    { .mask = (1 << 16), .value = TPMA_NV_PPREAD, .name = { "ppread", } },
    { .mask = (1 << 17), .value = TPMA_NV_OWNERREAD, .name = { "ownerread", } },
    { .mask = (1 << 18), .value = TPMA_NV_AUTHREAD, .name = { "authread", } },
    { .mask = (1 << 19), .value = TPMA_NV_POLICYREAD, .name = { "policyread", } },
    { .mask = (1 << 25), .value = TPMA_NV_NO_DA, .name = { "no_da", } },
    { .mask = (1 << 26), .value = TPMA_NV_ORDERLY, .name = { "orderly", } },
    { .mask = (1 << 27), .value = TPMA_NV_CLEAR_STCLEAR, .name = { "clear_stclear", } },
    { .mask = (1 << 28), .value = TPMA_NV_READLOCKED, .name = { "readlocked", } },
    { .mask = (1 << 29), .value = TPMA_NV_WRITTEN, .name = { "written", } },
    { .mask = (1 << 30), .value = TPMA_NV_PLATFORMCREATE, .name = { "platformcreate", } },
    { .mask = (1 << 31), .value = TPMA_NV_READ_STCLEAR, .name = { "read_stclear", } },
};


char *tpm2_attr_util_nv_attrtostr(TPMA_NV nvattrs) {
    if (nvattrs == 0) {
        char *ret = strdup("<none>");
        if (!ret) {
            LOG_ERR("Failed to allocate memory for NV attribute string");
        }
        return ret;
    } else {
        return attrstrmap_attr_to_string(nv_attr_map, ARRAY_LEN(nv_attr_map), nvattrs);
    }
}

bool tpm2_attr_util_nv_strtoattr(char *attribute_list, TPMA_NV *nvattrs) {
    return attrstrmap_string_to_attr(nv_attr_map, ARRAY_LEN(nv_attr_map), attribute_list, nvattrs);
}

static const attrstrmap obj_attr_map[] = {
    { .mask = (1 << 1), .value = TPMA_OBJECT_FIXEDTPM, .name = { "fixedtpm", } },
    { .mask = (1 << 2), .value = TPMA_OBJECT_STCLEAR, .name = { "stclear", } },
    { .mask = (1 << 4), .value = TPMA_OBJECT_FIXEDPARENT, .name = { "fixedparent", } },
    { .mask = (1 << 5), .value = TPMA_OBJECT_SENSITIVEDATAORIGIN, .name = { "sensitivedataorigin", } },
    { .mask = (1 << 6), .value = TPMA_OBJECT_USERWITHAUTH, .name = { "userwithauth", } },
    { .mask = (1 << 7), .value = TPMA_OBJECT_ADMINWITHPOLICY, .name = { "adminwithpolicy", } },
    { .mask = (1 << 10), .value = TPMA_OBJECT_NODA, .name = { "noda", } },
    { .mask = (1 << 11), .value = TPMA_OBJECT_ENCRYPTEDDUPLICATION, .name = { "encryptedduplication", } },
    { .mask = (1 << 16), .value = TPMA_OBJECT_RESTRICTED, .name = { "restricted", } },
    { .mask = (1 << 17), .value = TPMA_OBJECT_DECRYPT, .name = { "decrypt", } },
    { .mask = (1 << 18), .value = TPMA_OBJECT_SIGN_ENCRYPT, .name = { "sign", } },
};

char *tpm2_attr_util_obj_attrtostr(TPMA_OBJECT objattrs) {
    if (objattrs == 0) {
        char *ret = strdup("<none>");
        if (!ret) {
            LOG_ERR("Failed to allocate memory for object attribute string");
        }
        return ret;
    } else {
        return attrstrmap_attr_to_string(obj_attr_map, ARRAY_LEN(obj_attr_map), objattrs);
    }
}

bool tpm2_attr_util_obj_strtoattr(char *argvalue, TPMA_OBJECT *objattrs) {
    return attrstrmap_string_to_attr(obj_attr_map, ARRAY_LEN(obj_attr_map), argvalue, objattrs);
}

bool tpm2_attr_util_obj_from_optarg(char *argvalue, TPMA_OBJECT *objattrs) {

    bool res = tpm2_util_string_to_uint32(argvalue, objattrs);
    if (!res) {
        res = tpm2_attr_util_obj_strtoattr(argvalue, objattrs);
    }

    return res;
}
