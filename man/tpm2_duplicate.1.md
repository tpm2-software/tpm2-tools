tpm2_duplicate 1 "APRIL 2019" tpm2-tools
==================================================

# NAME

tpm2_duplicate(8) -  Duplicates a loaded object so that it may be used in a different hierarchy.

# SYNOPSIS

**tpm2_import** [*OPTIONS*]

# DESCRIPTION

This tool imports an external generated key as TPM managed key object.
It requires that the parent key object be of type RSA key.

# OPTIONS

These options control the key importation process:

  * **-G**, **--inner-wrapper-alg**=_ALGORITHM_:
    The symmetric algorithm to be used for the inner wrapper. Supports:
    * aes - AES 128 key.
    * null - none

  * **-k**, **--input-key-file**=_FILE_:
    Specifies the filename of the symmetric key (128 bit data) to be used for the inner wrapper. Valid only when --inner-wrapper-alg != null

  * **-K**, **--output-key-file**=_FILE_:
    Specifies the filename to store the symmetric key (128 bit data) that was used for the inner wrapper. Valid only when --inner-wrapper-alg != null and --input-key-file is not specified

  * **-C**, **--parent-key**=_PARENT\_CONTEXT_:
    Specifies the context object for the parent key. Either a file or a handle number.

  * **-r**, **--duplicate-key-private**=_FILE_:
    Specifies the file path to save the private portion of the duplicated object.

  * **-S**, **--output-enc-seed-file**=_FILE_:
    Specifies the file path required to save the encrypted seed of the duplicated
    object.

  * **-p**, **--auth-key**=_KEY\_AUTH_:
    The authorization value for the key, optional.
    Follows the authorization formatting of the
    "password for parent key" option: **-P**.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

To duplicate a key, one needs the key to duplicate, created with a policy that allows duplication and a new parent:
```
tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat -o policy.dat 0x14B
tpm2_flushcontext -S session.dat

tpm2_createprimary -a o -g sha256 -G rsa -o primary.ctxt
tpm2_create -C primary.ctxt -g sha256 -G rsa -r key.prv -u key.pub -L policy.dat -b "sensitivedataorigin"

tpm2_loadexternal -a o -u new_parent.pub -o new_parent.ctxt

tpm2_startauthsession --policy-session -S session.dat
tpm2_policycommandcode -S session.dat -o policy.dat 0x14B
tpm2_duplicate -C new_parent.ctxt -c key.ctxt -G null -p "session:session.dat" -r duprv.bin -S seed.dat
tpm2_flushcontext -S session.dat
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
