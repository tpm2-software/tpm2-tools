#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "tpm2_password_util.h"
#include "tpm2_util.h"

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LEN sizeof(HEX_PREFIX) - 1

#define STR_PREFIX "str:"
#define STR_PREFIX_LEN sizeof(STR_PREFIX) - 1

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
