% tpm2_getsessionauditdigest(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_getsessionauditdigest**(1) - Retrieve the command audit attestation data
from the TPM.

# SYNOPSIS

**tpm2_getsessionauditdigest** [*OPTIONS*]

# DESCRIPTION

**tpm2_getsessionauditdigest**(1) - Retrieve the session audit digest
attestation data from the TPM. The attestation data includes the session audit
digest and a signature over the session audit digest. The session itself is
started with the **tpm2_startauthsession** command.

# OPTIONS

  * **-P**, **\--hierarchy-auth**=_AUTH_:

    Specifies the authorization value for the endorsement hierarchy.

  * **-c**, **\--key-context**=_OBJECT_:

    Context object for the signing key that signs the attestation data.

  * **-p**, **\--auth**=_AUTH_:

    Specifies the authorization value for key specified by option **-c**.

  * **-q**, **\--qualification**=_HEX\_STRING\_OR\_PATH_:

    Data given as a Hex string or binary file to qualify the quote, optional.
    This is typically used to add a nonce against replay attacks.

  * **-s**, **\--signature**=_FILE_:

    Signature output file, records the signature in the format specified via the
    **-f** option.

  * **-m**, **\--message**=_FILE_:

    Message output file, records the quote message that makes up the data that
    is signed by the TPM. This is the command audit digest attestation data.

  * **-f**, **\--format**=_FORMAT_:

    Format selection for the signature output file.

  * **-g**, **\--hash-algorithm**:

    Hash algorithm for signature. Defaults to sha256.

  * **\--scheme**=_ALGORITHM_:

    The signing scheme used to sign the message. Optional.
    Signing schemes should follow the "formatting standards", see section
     "Algorithm Specifiers".
    Also, see section "Supported Signing Schemes" for a list of supported
     signature schemes.
    If specified, the signature scheme must match the key type.
    If left unspecified, a default signature scheme for the key type will
     be used.

  * **-S**, **\--session**=_FILE_:

    The path of the session that enables and records the audit digests.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[signature format specifiers](common/signature.md) option used to configure
signature _FORMAT_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

```bash
tpm2_createprimary -Q -C e -c prim.ctx

tpm2_create -Q -C prim.ctx -c signing_key.ctx -u signing_key.pub \
-r signing_key.priv

tpm2_startauthsession -S session.ctx --audit-session

tpm2_getrandom 8 -S session.ctx

tpm2_getsessionauditdigest -c signing_key.ctx -m att.data -s att.sig \
-S session.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
