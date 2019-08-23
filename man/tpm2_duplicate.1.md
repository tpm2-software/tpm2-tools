% tpm2_duplicate(1) tpm2-tools | General Commands Manual

# NAME

tpm2_duplicate(1) -  Duplicates a loaded object so that it may be used in a
different hierarchy.

# SYNOPSIS

**tpm2_duplicate** [*OPTIONS*]

# DESCRIPTION

**tpm2_duplicate**(1) - This tool duplicates a loaded object so that it may be
used in a different hierarchy. The new parent key for the duplicate may be on
the same or different TPM or TPM_RH_NULL.

# OPTIONS

These options control the key importation process:

  * **-G**, **\--wrapper-algorithm**=_ALGORITHM_:

    The symmetric algorithm to be used for the inner wrapper. Supports:
    * aes - AES 128 in CFB mode.
    * null - none

  * **-i**, **\--encryptionkey-in**=_FILE_:

    Specifies the filename of the symmetric key (128 bit data) to be used for
    the inner wrapper. Valid only when specified symmetric algorithm is not null

  * **-o**, **\--encryptionkey-out**=_FILE_:

    Specifies the filename to store the symmetric key (128 bit data) that was
    used for the inner wrapper. Valid only when specified symmetric algorithm is
    not null and \--input-key-file is not specified. The TPM generates the key
    in this case.

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent key object.

  * **-r**, **\--private**=_FILE_:

    Specifies the file path to save the private portion of the duplicated object.

  * **-s**, **\--encrypted-seed**=_FILE_:

    The file to save the encrypted seed of the duplicated object.

  * **-p**, **\--auth**=_AUTH_:

    The authorization value for the key, optional.

  * **-c**, **\--key-context**=_OBJECT_:

    The object to be duplicated.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

To duplicate a key, one needs the key to duplicate, created with a policy that \
allows duplication and a new parent:
```bash
tpm2_startauthsession -S session.dat
tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate
tpm2_flushcontext session.dat

tpm2_createprimary -C o -g sha256 -G rsa -c primary.ctxt
tpm2_create -C primary.ctxt -g sha256 -G rsa -r key.prv -u key.pub \
-L policy.dat -a "sensitivedataorigin"

tpm2_loadexternal -C o -u new_parent.pub -c new_parent.ctxt

tpm2_startauthsession \--policy-session -S session.dat
tpm2_policycommandcode -S session.dat -L policy.dat TPM2_CC_Duplicate
tpm2_duplicate -C new_parent.ctxt -c key.ctxt -G null -p "session:session.dat" \
-r duprv.bin -s seed.dat
tpm2_flushcontext session.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
