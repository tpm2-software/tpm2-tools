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
    { .name = str(x), .has_argument = false, .callback=x }

#define dispatch_arg_add(x) \
    { .name = str(x), .has_argument = true, .callback=x }

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
    bool has_argument;
    action callback;
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

static dispatch_table dtable[] = {
    dispatch_no_arg_add(authread),
    dispatch_no_arg_add(authwrite),
    dispatch_no_arg_add(clear_stclear),
    dispatch_no_arg_add(globallock),
    dispatch_no_arg_add(no_da),
    dispatch_no_arg_add(orderly),
    dispatch_no_arg_add(ownerread),
    dispatch_no_arg_add(ownerwrite),
    dispatch_no_arg_add(platformcreate),
    dispatch_no_arg_add(policyread),
    dispatch_no_arg_add(policywrite),
    dispatch_no_arg_add(policydelete),
    dispatch_no_arg_add(ppread),
    dispatch_no_arg_add(ppwrite),
    dispatch_no_arg_add(readlocked),
    dispatch_no_arg_add(read_stclear),
    dispatch_no_arg_add(writeall),
    dispatch_no_arg_add(writedefine),
    dispatch_no_arg_add(writelocked),
    dispatch_no_arg_add(write_stclear),
    dispatch_no_arg_add(written),
    dispatch_arg_add(nt)
};

static dispatch_error handle_dispatch(dispatch_table *d, char *token,
        TPMA_NV *nvattrs) {

    char *name = d->name;
    action cb = d->callback;
    bool has_arg = d->has_argument;

    /*
     * If it has an argument, split it on the equals sign if found.
     */
    char *arg = NULL;
    if (has_arg) {
        char *tmp = strchr(token, '=');
        if (!tmp) {
            LOG_ERR("Expected argument for \"%s\", got none.", token);
            return dispatch_err;
        }

        /* split token on = */
        *tmp = '\0';
        tmp++;
        if (!tmp) {
            LOG_ERR("Expected argument for \"%s\", got none.", token);
            return dispatch_err;
        }

        /* valid argument string, assign */
        arg = tmp;
    }

    if (strcmp(name, token)) {
        return dispatch_no_match;
    }

    bool result = cb(nvattrs, arg);
    return result ? dispatch_ok : dispatch_err;
}

bool tpm2_nv_util_attrs_to_val(char *attribute_list, TPMA_NV *nvattrs) {

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

    while ((token = strtok_r(attribute_list, "|", &save))) {
        attribute_list = NULL;

        bool did_dispatch = false;

        size_t i;
        for (i = 0; i < ARRAY_LEN(dtable); i++) {
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
