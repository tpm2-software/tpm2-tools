#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_nv_util.h"
#include "tpm2_util.h"

#define xstr(s) str(s)
#define str(s) #s

#define dispatch_no_arg_add(x) \
    { .name = str(x), .callback=x, .width = 1 }

#define dispatch_arg_add(x, w) \
    { .name = str(x), .callback=x, .width = w }

#define dispatch_reserved(pos) \
    { .name = "<reserved("xstr(pos)")>", .callback=NULL, .width = 1 }

typedef enum dispatch_error dispatch_error;
enum dispatch_error {
    dispatch_ok = 0,
    dispatch_err,
    dispatch_no_match,
};

typedef bool (*action)(TPMA_NV *nv, char *arg);

typedef struct dispatch_table dispatch_table;
struct dispatch_table {
    char *name;
    action callback;
    unsigned width; /* the width of the field, CANNOT be 0 */
};

static bool authread(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_AUTHREAD = 1;
    return true;
}

static bool authwrite(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_AUTHWRITE = 1;
    return true;
}

static bool clear_stclear(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_CLEAR_STCLEAR = 1;
    return true;
}

static bool globallock(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_GLOBALLOCK = 1;
    return true;
}

static bool no_da(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_NO_DA = 1;
    return true;
}

static bool orderly(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_ORDERLY = 1;
    return true;
}

static bool ownerread(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_OWNERREAD = 1;
    return true;
}

static bool ownerwrite(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_OWNERWRITE = 1;
    return true;
}

static bool platformcreate(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_PLATFORMCREATE = 1;
    return true;
}

static bool policyread(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_POLICYREAD = 1;
    return true;
}

static bool policywrite(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_POLICYWRITE = 1;
    return true;
}

static bool policydelete(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_POLICY_DELETE = 1;
    return true;
}

static bool ppread(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_PPREAD = 1;
    return true;
}

static bool ppwrite(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_PPWRITE = 1;
    return true;
}

static bool readlocked(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_READLOCKED = 1;
    return true;
}

static bool read_stclear(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_READ_STCLEAR = 1;
    return true;
}

static bool writeall(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_WRITEALL = 1;
    return true;
}

static bool writedefine(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_WRITEDEFINE = 1;
    return true;
}

static bool writelocked(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_WRITELOCKED = 1;
    return true;
}

static bool write_stclear(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_WRITE_STCLEAR = 1;
    return true;
}

static bool written(TPMA_NV *nv, char *arg) {

    (void) arg;
    nv->TPMA_NV_WRITTEN = 1;
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

    nv->TPM_NT = value;
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
static dispatch_table dtable[] = {       // Bit Index
    dispatch_no_arg_add(ppwrite),        //  0
    dispatch_no_arg_add(ownerwrite),     //  1
    dispatch_no_arg_add(authwrite),      //  2
    dispatch_no_arg_add(policywrite),    //  3
    dispatch_arg_add(nt, 4),             //  4
    dispatch_arg_add(nt, 3),             //  5
    dispatch_arg_add(nt, 2),             //  6
    dispatch_arg_add(nt, 1),             //  7
    dispatch_reserved(8),                //  8
    dispatch_reserved(9),                //  9
    dispatch_no_arg_add(policydelete),   // 10
    dispatch_no_arg_add(writelocked),    // 11
    dispatch_no_arg_add(writeall),       // 12
    dispatch_no_arg_add(writedefine),    // 13
    dispatch_no_arg_add(write_stclear),  // 14
    dispatch_no_arg_add(globallock),     // 15
    dispatch_no_arg_add(ppread),         // 16
    dispatch_no_arg_add(ownerread),      // 17
    dispatch_no_arg_add(authread),       // 18
    dispatch_no_arg_add(policyread),     // 19
    dispatch_reserved(20),               // 20
    dispatch_reserved(21),               // 21
    dispatch_reserved(22),               // 22
    dispatch_reserved(23),               // 23
    dispatch_reserved(24),               // 24
    dispatch_no_arg_add(no_da),          // 25
    dispatch_no_arg_add(orderly),        // 26
    dispatch_no_arg_add(clear_stclear),  // 27
    dispatch_no_arg_add(readlocked),     // 28
    dispatch_no_arg_add(written),        // 29
    dispatch_no_arg_add(platformcreate), // 30
    dispatch_no_arg_add(read_stclear),   // 31
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

bool tpm2_nv_util_strtoattr(char *attribute_list, TPMA_NV *nvattrs) {

    char *token;
    char *save;

    /*
     * This check is soley to prevent GCC from complaining on:
     * error: ‘attribute_list’ may be used uninitialized in this function [-Werror=maybe-uninitialized]
     * Might as well check nvattrs as well.
     */
    if (!attribute_list || !nvattrs) {
        LOG_ERR("attribute listr or nvattrs is NULL");
        return false;
    }

    size_t dlen = ARRAY_LEN(dtable);

    while ((token = strtok_r(attribute_list, "|", &save))) {
        attribute_list = NULL;

        bool did_dispatch = false;

        size_t i;
        for (i = 0; i < dlen; i++) {
            dispatch_table *d = &dtable[i];

            dispatch_error err = handle_dispatch(d, token, nvattrs);
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

char *tpm2_nv_util_attrtostr(TPMA_NV nvattrs) {

    if (nvattrs.val == 0) {
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
    UINT32 pop_cnt = tpm2_util_pop_count(nvattrs.val);

    size_t i;
    size_t max_name_len = 0;
    for (i=0; i < ARRAY_LEN(dtable); i++) {
        dispatch_table *d = &dtable[i];
        size_t name_len = strlen(d->name);
        max_name_len = name_len > max_name_len ? name_len : max_name_len;
    }

    size_t size = pop_cnt * max_name_len + pop_cnt - 1 + 3;

    char *str = calloc(size, 1);
    if (!str) {
        return NULL;
    }


    size_t string_index = 0;
    UINT32 attrs = nvattrs.val;

    /*
     * Start at the lowest, first bit set, index into the array,
     * grab the data needed, and move on.
     */
    while (attrs) {
        UINT8 bit_index = find_first_set(attrs);

        dispatch_table *d = &dtable[bit_index];

        const char *name = d->name;
        unsigned w = d->width;

        /* current position and size left of the string */
        char *s = &str[string_index];
        size_t left = size - string_index;

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

TPM_RC tpm2_util_nv_read_public(TSS2_SYS_CONTEXT *sapi_context,
        TPMI_RH_NV_INDEX nv_index, TPM2B_NV_PUBLIC *nv_public) {

    TPM2B_NAME nv_name = TPM2B_TYPE_INIT(TPM2B_NAME, name);

    return Tss2_Sys_NV_ReadPublic(sapi_context, nv_index, 0, nv_public,
            &nv_name, 0);
}
