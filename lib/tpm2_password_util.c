#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_password_util.h"
#include "tpm2_util.h"

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LEN sizeof(HEX_PREFIX) - 1

#define STR_PREFIX "str:"
#define STR_PREFIX_LEN sizeof(STR_PREFIX) - 1

#define PASSWORD_MAX (sizeof(((TPM2B_DIGEST *)NULL)->t.buffer))

bool tpm2_password_util_from_optarg(const char *password, TPM2B_AUTH *dest) {

    bool is_hex = !strncmp(password, HEX_PREFIX, HEX_PREFIX_LEN);
    if (!is_hex) {

        /* str may or may not have the str: prefix */
        bool is_str_prefix = !strncmp(password, STR_PREFIX, STR_PREFIX_LEN);
        if (is_str_prefix) {
            password += STR_PREFIX_LEN;
        }

        /*
         * Per the man page:
         * "a return value of size or more means that the output was  truncated."
         */
        size_t wrote = snprintf((char *)&dest->t.buffer, BUFFER_SIZE(typeof(*dest), buffer), "%s", password);
        if (wrote >= BUFFER_SIZE(typeof(*dest), buffer)) {
            dest->t.size = 0;
            return false;
        }

        dest->t.size = wrote;

        return true;
    }

    /* if it is hex, then skip the prefix */
    password += HEX_PREFIX_LEN;

    dest->t.size = BUFFER_SIZE(typeof(*dest), buffer);
    int rc = tpm2_util_hex_to_byte_structure(password, &dest->t.size, dest->t.buffer);
    if (rc) {
        dest->t.size = 0;
        return false;
    }

    return true;
}

bool tpm2_password_util_fromhex(TPM2B_AUTH *password, bool is_hex, const char *description,
        TPM2B_AUTH *auth) {

    if (is_hex) {
        auth->t.size = sizeof(auth) - 2;
        /* this routine is safe on overlapping memory areas */
        if (tpm2_util_hex_to_byte_structure((char *)password->t.buffer, &auth->t.size, auth->t.buffer)
                != 0) {
            LOG_ERR("Failed to convert hex format password for %s.",
                    description);
            return false;
        }
        /*
         * we only claim sanity on same memory, not overlapping, but well use
         * memove anyways at the expense of speed.
         */
    } else if (password != auth) {
        memmove(auth, password, sizeof(*auth));
    }
    return true;
}

bool tpm2_password_util_copy_password(const char *password, const char *description, TPM2B_AUTH *dest) {

    if (!password) {
        LOG_ERR("Please input the %s password!", description);
        return false;
    }

    if (!dest || !description) {
        return false;
    }

    size_t len = strlen(password);
    if (len >= PASSWORD_MAX) {
        LOG_ERR("Over-length password for %s. Got %zu expected less than %zu!", description, len, PASSWORD_MAX);
        return false;
    }

    dest->t.size = len;
    snprintf((char *)dest->t.buffer, PASSWORD_MAX, "%s", password);
    return true;
}
