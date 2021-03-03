% tpm2_activatecredential(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_activatecredential**(1) - Enables access to the credential qualifier to
recover the credential secret.

# SYNOPSIS

**tpm2_activatecredential** [*OPTIONS*]

# DESCRIPTION

**tpm2_activatecredential**(1) - Enables the association of a credential with an
object in a way that ensures that the TPM has validated the parameters of the
credentialed object. In an attestation scheme , this guarantees the registrar
that the attestation key belongs to the TPM with a qualified parent key in the
TPM.

# OPTIONS

  * **-c**, **\--credentialedkey-context**=_OBJECT_:

    Object associated with the created certificate by CA.

  * **-C**, **\--credentialkey-context**=_OBJECT_:

    The loaded object used to decrypt the random seed.

  * **-p**, **\--credentialedkey-auth**=_AUTH_:

    The auth value of the credentialed object specified with **-c**.

  * **-P**, **\--credentialkey-auth**=_AUTH_:

    The auth value of the credential object specified with **-C**.

  * **-i**, **\--credential-blob**=_FILE_:

    The input file path containing the credential blob and secret created with
    the **tpm2_makecredential**(1) tool.

  * **-o**, **\--certinfo-data**=_FILE_:

    The output file path to save the decrypted credential secret information.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash, unless rphash is also required.

  * **\--rphash**=_FILE_

    File path to record the hash of the response parameters. This is commonly
    termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. This can be used to
    specify an auxiliary session for auditing and or encryption/decryption of
    the parameters.

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
echo "12345678" > secret.data

tpm2_createek -Q -c 0x81010001 -G rsa -u ek.pub

tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub \
-n ak.name -p akpass> ak.out

file_size=`stat --printf="%s" ak.name`
loaded_key_name=`cat ak.name | xxd -p -c $file_size`

tpm2_makecredential -Q -e ek.pub  -s secret.data -n $loaded_key_name \
-o mkcred.out

tpm2_startauthsession --policy-session -S session.ctx

tpm2_policysecret -S session.ctx -c e

tpm2_activatecredential -Q -c ak.ctx -C 0x81010001 -i mkcred.out \
-o actcred.out -p akpass -P"session:session.ctx"

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
