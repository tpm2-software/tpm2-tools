#include <stdbool.h>

#include <sapi/tpm20.h>

#include "log.h"
#include "password_util.h"
#include "string-bytes.h"

#define PASSWORD_MAX (sizeof(((TPM2B_DIGEST *)NULL)->t.buffer))

bool password_util_to_auth(TPM2B_AUTH *password, bool is_hex, const char *description,
        TPM2B_AUTH *auth) {

    if (is_hex) {
        auth->t.size = sizeof(auth) - 2;
        /* this routine is safe on overlapping memory areas */
        if (hex2ByteStructure(password->t.buffer, &auth->t.size, auth->t.buffer)
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

bool password_util_copy_password(const char *password, const char *description, TPM2B_AUTH *dest) {

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
    snprintf(dest->t.buffer, PASSWORD_MAX, "%s", password);
    return true;
}
