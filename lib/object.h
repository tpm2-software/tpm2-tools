#ifndef LIB_OBJECT_H_
#define LIB_OBJECT_H_

#include "tool_rc.h"
#include "tpm2_session.h"
#include "tpm2_util.h"

#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/asn1.h>
#include <openssl/asn1t.h>
#include <tss2/tss2_mu.h>

typedef struct tpm2_loaded_object tpm2_loaded_object;
struct tpm2_loaded_object {
    TPM2_HANDLE handle;
    ESYS_TR tr_handle;
    const char *path;
    tpm2_session *session;
};

typedef struct {
    ASN1_OBJECT *type;
    ASN1_BOOLEAN emptyAuth;
    ASN1_INTEGER *parent;
    ASN1_OCTET_STRING *pubkey;
    ASN1_OCTET_STRING *privkey;
} TSSPRIVKEY_OBJ;

#define OID_loadableKey "2.23.133.10.1.3"
#define TSSPRIVKEY_OBJ_PEM_STRING "TSS2 PRIVATE KEY"

DECLARE_ASN1_FUNCTIONS(TSSPRIVKEY_OBJ);
DECLARE_PEM_write_bio(TSSPRIVKEY_OBJ, TSSPRIVKEY_OBJ);
DECLARE_PEM_read_bio(TSSPRIVKEY_OBJ, TSSPRIVKEY_OBJ);

/*
 * TPM2B_PRIVATE and TPM2B_PUBLIC parsed from a TSSPEM/ tssprivkey
 */
extern TPM2B_PRIVATE tpm2_util_object_tsspem_priv;
extern TPM2B_PUBLIC tpm2_util_object_tsspem_pub;

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

/**
 * Fetches the unmarshalled public and private portions of the
 * TSS Privkey object.
 * 
 * @param objectstr
 * Path to file containing the TSS PRIVKEY object.
 * @param pub
 * The unmarshalled public portion of TSS Private Key.
 * @param priv
 * The unmarshalled private portion of TSS Private Key.
 * @return
 *  tool_rc indicating the status.
 */
tool_rc tpm2_util_object_fetch_priv_pub_from_tpk(const char *objectstr,
        TPM2B_PUBLIC *pub, TPM2B_PRIVATE *priv);

/**
 * Fetch TPK parent value as a long int
 * 
 * @param objectstr
 * Path to file containing the TSS PRIVKEY object.
 * @param val
 * Parent value in long int
 * @return
 *  tool_rc indicating the status.
 */
tool_rc tpm2_util_object_fetch_parent_from_tpk(const char *objectstr,
        uint64_t *val);

#endif /* LIB_OBJECT_H_ */
