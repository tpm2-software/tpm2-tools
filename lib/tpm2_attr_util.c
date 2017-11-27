//**********************************************************************;
// Copyright (c) 2017, Intel Corporation
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
// 3. Neither the name of Intel Corporation nor the names of its contributors
// may be used to endorse or promote products derived from this software without
// specific prior written permission.
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
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_attr_util.h"
#include "tpm2_util.h"

#define dispatch_no_arg_add(x) \
    { .name = str(x), .callback=(action)x, .width = 1 }

#define dispatch_arg_add(x, w) \
    { .name = str(x), .callback=(action)x, .width = w }

#define dispatch_reserved(pos) \
    { .name = "<reserved("xstr(pos)")>", .callback=NULL, .width = 1 }

typedef enum dispatch_error dispatch_error;
enum dispatch_error {
    dispatch_ok = 0,
    dispatch_err,
    dispatch_no_match,
};

typedef bool (*action)(void *obj, char *arg);

typedef struct dispatch_table dispatch_table;
struct dispatch_table {
    char *name;
    action callback;
    unsigned width; /* the width of the field, CANNOT be 0 */
};

static bool authread(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_AUTHREAD;
    return true;
}

static bool authwrite(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_AUTHWRITE;
    return true;
}

static bool clear_stclear(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_CLEAR_STCLEAR;
    return true;
}

static bool globallock(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_GLOBALLOCK;
    return true;
}

static bool no_da(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_NO_DA;
    return true;
}

static bool orderly(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_ORDERLY;
    return true;
}

static bool ownerread(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_OWNERREAD;
    return true;
}

static bool ownerwrite(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_OWNERWRITE;
    return true;
}

static bool platformcreate(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_PLATFORMCREATE;
    return true;
}

static bool policyread(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_POLICYREAD;
    return true;
}

static bool policywrite(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_POLICYWRITE;
    return true;
}

static bool policydelete(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_POLICY_DELETE;
    return true;
}

static bool ppread(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_PPREAD;
    return true;
}

static bool ppwrite(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_PPWRITE;
    return true;
}

static bool readlocked(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_READLOCKED;
    return true;
}

static bool read_stclear(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_READ_STCLEAR;
    return true;
}

static bool writeall(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_WRITEALL;
    return true;
}

static bool writedefine(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_WRITEDEFINE;
    return true;
}

static bool writelocked(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_WRITELOCKED;
    return true;
}

static bool write_stclear(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_WRITE_STCLEAR;
    return true;
}

static bool written(TPMA_NV *nv, char *arg) {

    UNUSED(arg);
    *nv |= TPMA_NV_TPMA_NV_WRITTEN;
    return true;
}

static bool nt(TPMA_NV *nv, char *arg) {

    uint16_t value;
    bool result = tpm2_util_string_to_uint16(arg, &value);
    if (!result) {
        LOG_ERR("Could not convert \"%s\", to a number", arg);
        return false;
    }

    /* nt space is 4 bits, so max of 15 */
    if (value > 0x0F) {
        LOG_ERR("Field TPM_NT of type TPMA_NV is only 4 bits,"
                "value \"%s\" to big!", arg);
        return false;
    }

    *nv &= ~TPMA_NV_TPM2_NT;
    *nv |= value << 4;
    return true;
}

/*
 * The order of this table must be in order with the bit defines in table 204:
 * https://trustedcomputinggroup.org/wp-content/uploads/TPM-Rev-2.0-Part-2-Structures-01.38.pdf
 *
 * This table is in bitfield order, thus the index of a bit set in a TPMA_NV
 * can be used to lookup the name.
 *
 * if not the logic in tpm2_nv_util_strtoattr would need to change!
 */
static dispatch_table nv_attr_table[] = { // Bit Index
    dispatch_no_arg_add(ppwrite),         //  0
    dispatch_no_arg_add(ownerwrite),      //  1
    dispatch_no_arg_add(authwrite),       //  2
    dispatch_no_arg_add(policywrite),     //  3
    dispatch_arg_add(nt, 4),              //  4
    dispatch_arg_add(nt, 3),              //  5
    dispatch_arg_add(nt, 2),              //  6
    dispatch_arg_add(nt, 1),              //  7
    dispatch_reserved(8),                 //  8
    dispatch_reserved(9),                 //  9
    dispatch_no_arg_add(policydelete),    // 10
    dispatch_no_arg_add(writelocked),     // 11
    dispatch_no_arg_add(writeall),        // 12
    dispatch_no_arg_add(writedefine),     // 13
    dispatch_no_arg_add(write_stclear),   // 14
    dispatch_no_arg_add(globallock),      // 15
    dispatch_no_arg_add(ppread),          // 16
    dispatch_no_arg_add(ownerread),       // 17
    dispatch_no_arg_add(authread),        // 18
    dispatch_no_arg_add(policyread),      // 19
    dispatch_reserved(20),                // 20
    dispatch_reserved(21),                // 21
    dispatch_reserved(22),                // 22
    dispatch_reserved(23),                // 23
    dispatch_reserved(24),                // 24
    dispatch_no_arg_add(no_da),           // 25
    dispatch_no_arg_add(orderly),         // 26
    dispatch_no_arg_add(clear_stclear),   // 27
    dispatch_no_arg_add(readlocked),      // 28
    dispatch_no_arg_add(written),         // 29
    dispatch_no_arg_add(platformcreate),  // 30
    dispatch_no_arg_add(read_stclear),    // 31
};

static bool fixedtpm(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_FIXEDTPM;
    return true;
}

static bool stclear(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_STCLEAR;
    return true;
}

static bool fixedparent(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_FIXEDPARENT;
    return true;
}

static bool sensitivedataorigin(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_SENSITIVEDATAORIGIN;
    return true;
}

static bool userwithauth(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_USERWITHAUTH;
    return true;
}

static bool adminwithpolicy(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_ADMINWITHPOLICY;
    return true;
}

static bool noda(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_NODA;
    return true;
}

static bool encryptedduplication(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_ENCRYPTEDDUPLICATION;
    return true;
}

static bool restricted(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_RESTRICTED;
    return true;
}

static bool decrypt(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_DECRYPT;
    return true;
}

static bool sign(TPMA_OBJECT *obj, char *arg) {

    UNUSED(arg);
    *obj |= TPMA_OBJECT_SIGN;
    return true;
}

static dispatch_table obj_attr_table[] = {         // Bit Index
        dispatch_reserved(0),                      //  0
        dispatch_no_arg_add(fixedtpm),             //  1
        dispatch_no_arg_add(stclear),              //  2
        dispatch_reserved(3),                      //  3
        dispatch_no_arg_add(fixedparent),          //  4
        dispatch_no_arg_add(sensitivedataorigin),  //  5
        dispatch_no_arg_add(userwithauth),         //  6
        dispatch_no_arg_add(adminwithpolicy),      //  7
        dispatch_reserved(8),                      //  8
        dispatch_reserved(9),                      //  9
        dispatch_no_arg_add(noda),                 // 10
        dispatch_no_arg_add(encryptedduplication), // 11
        dispatch_reserved(12),                     // 12
        dispatch_reserved(13),                     // 13
        dispatch_reserved(14),                     // 14
        dispatch_reserved(15),                     // 15
        dispatch_no_arg_add(restricted),           // 16
        dispatch_no_arg_add(decrypt),              // 17
        dispatch_no_arg_add(sign),                 // 18
        dispatch_reserved(19),                     // 19
        dispatch_reserved(20),                     // 20
        dispatch_reserved(21),                     // 21
        dispatch_reserved(22),                     // 22
        dispatch_reserved(23),                     // 23
        dispatch_reserved(24),                     // 24
        dispatch_reserved(25),                     // 25
        dispatch_reserved(26),                     // 26
        dispatch_reserved(27),                     // 27
        dispatch_reserved(28),                     // 28
        dispatch_reserved(29),                     // 29
        dispatch_reserved(30),                     // 30
        dispatch_reserved(31),                     // 31
};

static bool token_match(const char *name, const char *token, bool has_arg, char **sep) {

    /* if it has an argument, we expect a separator */
    size_t match_len = strlen(token);
    if (has_arg) {
        *sep = strchr(token, '=');
        if (*sep) {
            match_len = *sep - token;
        }
    }

    return !strncmp(name, token, match_len);
}

static dispatch_error handle_dispatch(dispatch_table *d, char *token,
        TPMA_NV *nvattrs) {

    char *name = d->name;
    action cb = d->callback;
    bool has_arg = d->width > 1;

    /* if no callback, then its a reserved block, just skip it */
    if (!cb) {
        return dispatch_no_match;
    }

    char *sep = NULL;
    bool match = token_match(name, token, has_arg, &sep);
    if (!match) {
        return dispatch_no_match;
    }

    /*
     * If it has an argument, match should have found the seperator.
     */
    char *arg = NULL;
    if (has_arg) {
        if (!sep) {
            LOG_ERR("Expected argument for \"%s\", got none.", token);
            return dispatch_err;
        }

        /* split token on = */
        *sep = '\0';
        sep++;
        if (!*sep) {
            LOG_ERR("Expected argument for \"%s\", got none.", token);
            return dispatch_err;
        }

        /* valid argument string, assign */
        arg = sep;
    }

    bool result = cb(nvattrs, arg);
    return result ? dispatch_ok : dispatch_err;
}

static bool common_strtoattr(char *attribute_list, void *attrs, dispatch_table *table, size_t size) {

    char *token;
    char *save;

    /*
     * This check is soley to prevent GCC from complaining on:
     * error: ‘attribute_list’ may be used uninitialized in this function [-Werror=maybe-uninitialized]
     * Might as well check nvattrs as well.
     */
    if (!attribute_list || !attrs) {
        LOG_ERR("attribute list or attributes structure is NULL");
        return false;
    }

    while ((token = strtok_r(attribute_list, "|", &save))) {
        attribute_list = NULL;

        bool did_dispatch = false;

        size_t i;
        for (i = 0; i < size; i++) {
            dispatch_table *d = &table[i];

            dispatch_error err = handle_dispatch(d, token, attrs);
            if (err == dispatch_ok) {
                did_dispatch = true;
                break;
            } else if (err == dispatch_err) {
                return false;
            }
            /* dispatch_no_match --> keep looking */
        }

        /* did we dispatch?, If not log error and return */
        if (!did_dispatch) {
            char *tmp = strchr(token, '=');
            if (tmp) {
                *tmp = '\0';
            }
            LOG_ERR("Unknown token: \"%s\" found.", token);
            return false;
        }
    }

    return true;
}

bool tpm2_attr_util_nv_strtoattr(char *attribute_list, TPMA_NV *nvattrs) {

    return common_strtoattr(attribute_list, nvattrs, nv_attr_table, ARRAY_LEN(nv_attr_table));
}

bool tpm2_attr_util_obj_strtoattr(char *attribute_list, TPMA_OBJECT *objattrs) {

    return common_strtoattr(attribute_list, objattrs, obj_attr_table, ARRAY_LEN(obj_attr_table));
}


static UINT8 find_first_set(UINT32 bits) {

    UINT8 n = 0;

    if (!bits) {
        return n;
    }

    if (!(bits & 0x0000FFFF)) { n += 16; bits >>= 16; }
    if (!(bits & 0x000000FF)) { n +=  8; bits >>=  8; }
    if (!(bits & 0x0000000F)) { n +=  4; bits >>=  4; }
    if (!(bits & 0x00000003)) { n +=  2; bits >>=  2; }
    if (!(bits & 0x00000001))   n +=  1;

    return n;
}

static char *tpm2_attr_util_common_attrtostr(UINT32 attrs, dispatch_table *table, size_t size) {

    if (attrs == 0) {
        return strdup("<none>");
    }

    /*
     * Get how many bits are set in the attributes and then find the longest
     * "name".
     *
     * pop_cnt * max_name_len + pop_cnt - 1 (for the | separators) + 4
     * (for nv field equals in hex) + 1 for null byte.
     *
     * This will provide us an ample buffer size for generating the string
     * in without having to constantly realloc.
     */
    UINT32 pop_cnt = tpm2_util_pop_count(attrs);

    size_t i;
    size_t max_name_len = 0;
    for (i=0; i < size; i++) {
        dispatch_table *d = &table[i];
        size_t name_len = strlen(d->name);
        max_name_len = name_len > max_name_len ? name_len : max_name_len;
    }

    size_t length = pop_cnt * max_name_len + pop_cnt - 1 + 3;

    char *str = calloc(length, 1);
    if (!str) {
        return NULL;
    }


    size_t string_index = 0;

    /*
     * Start at the lowest, first bit set, index into the array,
     * grab the data needed, and move on.
     */
    while (attrs) {
        UINT8 bit_index = find_first_set(attrs);

        dispatch_table *d = &table[bit_index];

        const char *name = d->name;
        unsigned w = d->width;

        /* current position and size left of the string */
        char *s = &str[string_index];
        size_t left = length - string_index;

        /* this is a mask that is field width wide */
        UINT8 mask = ((UINT32)1 << w) - 1;

        /* get the value in the field before clearing attrs out */
        UINT8 field_values = (attrs & mask << bit_index) >> bit_index;

        /*
         * turn off the parsed bit(s) index, using width to turn off everything in a
         * field
         */
        attrs &= ~(mask << bit_index);

        /*
         * if the callback is NULL, we are either in a field middle or reserved
         * section which is weird, just add the name in. In the case of being
         * in the middle of the field, we will add a bunch of errors to the string,
         * but it would be better to attempt to show all the data in string form,
         * rather than bail.
         *
         * Fields are either 1 or > 1.
         */
        if (w == 1) {
            /*
             * set the format to a middle output, unless we're parsing
             * the first or last. Let the format be static with the routine
             * so the compiler can do printf style format specifier checking.
             */
            if (!string_index) {
                /* on the first write, if we are already done, no pipes */
                string_index += !attrs ? snprintf(s, left, "%s", name) :
                        snprintf(s, left, "%s|", name);
            } else if (!attrs) {
                string_index += snprintf(s, left, "%s", name);
            } else {
                string_index += snprintf(s, left, "%s|", name);
            }
        } else {
            /* deal with the field */
            if (!string_index) {
                /* on the first write, if we are already done, no pipes */
                string_index += !attrs ? snprintf(s, left, "%s=0x%X", name, field_values) :
                        snprintf(s, left, "%s=0x%X|", name, field_values);
            } else if (!attrs) {
                string_index += snprintf(s, left, "%s=0x%X", name, field_values);
            } else {
                string_index += snprintf(s, left, "%s=0x%X|", name, field_values);
            }
        }
    }

    return str;
}

char *tpm2_attr_util_nv_attrtostr(TPMA_NV nvattrs) {
    return tpm2_attr_util_common_attrtostr(nvattrs, nv_attr_table, ARRAY_LEN(nv_attr_table));
}

char *tpm2_attr_util_obj_attrtostr(TPMA_OBJECT objattrs) {
    return tpm2_attr_util_common_attrtostr(objattrs, obj_attr_table, ARRAY_LEN(obj_attr_table));
}

bool tpm2_attr_util_obj_from_optarg(char *argvalue, TPMA_OBJECT *objattrs) {

    bool res = tpm2_util_string_to_uint32(argvalue, objattrs);
    if (!res) {
        res = tpm2_attr_util_obj_strtoattr(argvalue, objattrs);
    }

    return res;
}
