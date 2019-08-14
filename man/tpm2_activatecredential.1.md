% tpm2_activatecredential(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_activatecredential**(1) - Enables access to the credential qualifier to
recover the credential secret.

# SYNOPSIS

**tpm2_activatecredential** [*OPTIONS*]

# DESCRIPTION

**tpm2_activatecredential**(1) -  Enables the association of a credential with
an object in a way that ensures that the TPM has validated the parameters of the
credentialed object. In an attestation scheme , this guarantees the registrar that
the attestation key belongs to the TPM with a qualified parent key in the TPM.

# OPTIONS

These options control the object verification:

  * **-c**, **\--credentialedkey-context**=_CREDENTIALED\_KEY\_OBJ\_CTX\_OR\_HANDLE_:

    _CONTEXT\_OBJECT_ of the content object associated with the created
    certificate by CA. Either a file or a handle number. See section "Context
    Object Format".

  * **-C**, **\--credentialkey-context**=_CREDENTIAL\_KEY\_OBJ\_CTX\_OR\_HANDLE_:

    The _CREDENTIAL\_KEY\_OBJ\_CTX\_OR\_HANDLE_ of the loaded key used to decrypt the
    random seed. Either a file or a handle number. See section "Context Object
    Format".

  * **-p**, **\--credentialedkey-auth**=_AUTH\_VALUE_:

    _AUTH\_VALUE_ for providing an authorization value for the
    _CREDENTIALED\_KEY\_OBJ\_CTX\_OR\_HANDLE_.

  * **-P**, **\--credentialkey-auth**=_AUTH\_VALUE_:

    _AUTH\_VALUE_ for providing an authorization value for the
    _CREDENTIAL\_KEY\_OBJ\_CTX\_OR\_HANDLE_.

  * **-i**, **\--credential-blob**=_INPUT\_FILE_:

    Input file path, containing the two structures - credential blob and secret,
    needed by **tpm2_activatecredential**(1) function. This is created from the
    **tpm2_makecredential**(1) tool.

  * **-o**, **\--certinfo-data**=_OUTPUT\_FILE_:

    Output file path, record the decrypted credential secret information.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

```bash
echo "12345678" > secret.data

tpm2_createek -Q -c 0x81010001 -G rsa -u ek.pub

tpm2_createak -C 0x81010001 -c ak.ctx -G rsa -g sha256 -s rsassa -u ak.pub -n ak.name -p akpass> ak.out

file_size=`stat --printf="%s" ak.name`
loaded_key_name=`cat ak.name | xxd -p -c $file_size`

tpm2_makecredential -Q -e ek.pub  -s secret.data -n $loaded_key_name -o mkcred.out

tpm2_startauthsession --policy-session -S session.ctx

TPM2_RH_ENDORSEMENT=0x4000000B
tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT

tpm2_activatecredential -Q -c ak.ctx -C 0x81010001 -i mkcred.out -o actcred.out -p akpass -P"session:session.ctx"

tpm2_flushcontext session.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
