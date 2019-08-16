#ifndef LIB_OBJECT_H_
#define LIB_OBJECT_H_

#include "tool_rc.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object {
    TPM2_HANDLE handle;
    ESYS_TR tr_handle;
    const char *path;
    tpm2_session *session;
};

/**
 * Parses a string representation of a context object, either a file or handle,
 * and loads the context object ensuring the handle member of the out object is
 * set.
 * The objectstr will recognised as a context file when prefixed with "file:"
 * or should the value not be parsable as a handle number (as understood by
 * strtoul()).
 * @param ctx
 * a TSS ESAPI context.
 * @param objectstr
 * The string representation of the object to be loaded.
 * @param outobject
 * A *tpm2_loaded_object* with a loaded handle. The path member will also be
 * set when the *objectstr* is a context file.
 * @param flags
 * A *tpm2_hierarchy_flags* value to specify expected valid hierarchy
 * @return
 *  tool_rc indicating status.
 *
 */
tool_rc tpm2_util_object_load(ESYS_CONTEXT *ctx, const char *objectstr,
        tpm2_loaded_object *outobject, tpm2_handle_flags flags);

/**
 * Same as tpm2_util_object_load but allows the auth string value to be populated
 * as a session associated with the object.
 * @param ctx
 * a TSS ESAPI context.
 * @param objectstr
 * The string representation of the object to be loaded.
 * @param auth
 * The auth string for the object.
 * @param is_restricted_pswd_session
 * The auth session associated with the object is restricted to TPM2_RS_PW
 * @param outobject
 * A *tpm2_loaded_object* with a loaded handle. The path member will also be
 * set when the *objectstr* is a context file.
 * @param flags
 * A *tpm2_hierarchy_flags* value to specify expected valid hierarchy
 * @return
 *  tool_rc indicating status.
 * @return
 *  tool_rc indicating status
 */
tool_rc tpm2_util_object_load_auth(ESYS_CONTEXT *ctx, const char *objectstr,
        const char *auth, tpm2_loaded_object *outobject,
        bool is_restricted_pswd_session, tpm2_handle_flags flags);

#endif /* LIB_OBJECT_H_ */
