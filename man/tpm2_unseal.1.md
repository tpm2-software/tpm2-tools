% tpm2_unseal(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_unseal**(1) - Returns a data blob in a loaded TPM object. The data blob
is returned in clear.

# SYNOPSIS

**tpm2_unseal** [*OPTIONS*]

# DESCRIPTION

**tpm2_unseal**(1) - Returns a data blob in a loaded TPM object. The data blob
is returned in clear. The data is sealed at the time of the object creation
using the **tpm2_create** tool. Such an object intended for sealing data has to
be of the type _TPM\_ALG\_KEYEDHASH_.

# OPTIONS

  * **-c**, **\--object-context**=_OBJECT_:

    Object context for the loaded object.

  * **-p**, **\--auth**=_AUTH_:

    Optional auth value to use for the key specified by **-c**.

  * **-o**, **\--output**=_FILE_:

    Output file name containing the unsealed data. Defaults to _STDOUT_ if not
    specified.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, it simply returns
    a cpHash, unless rphash is also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. Multiple of these can
    be specified. For example, you can have one session for auditing and another
    for encryption/decryption of the parameters.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_createprimary -c primary.ctx -Q

tpm2_pcrread -Q -o pcr.bin sha256:0,1,2,3

tpm2_createpolicy -Q --policy-pcr -l sha256:0,1,2,3 -f pcr.bin -L pcr.policy

echo 'secret' | tpm2_create -C primary.ctx -L pcr.policy -i-\
-u seal.pub -r seal.priv -c seal.ctx -Q

tpm2_unseal -c seal.ctx -p pcr:sha256:0,1,2,3
```

[returns](common/returns.md)

[footer](common/footer.md)
