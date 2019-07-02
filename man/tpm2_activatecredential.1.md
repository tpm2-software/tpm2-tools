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

  * **-P**, **\--credentialedkey-auth**=_AUTH\_VALUE_:

    _AUTH\_VALUE_ for providing an authorization value for the
    _CREDENTIALED\_KEY\_OBJ\_CTX\_OR\_HANDLE_.

  * **-E**, **\--credentialkey-auth**=_AUTH\_VALUE_:

    _AUTH\_VALUE_ for providing an authorization value for the
    _CREDENTIAL\_KEY\_OBJ\_CTX\_OR\_HANDLE_.

  * **-i**, **\--credential-secret**=_INPUT\_FILE_:

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

```
TPM2_RH_ENDORSEMENT=0x4000000B
tpm2_startauthsession --policy-session -S session.ctx
tpm2_policysecret -S session.ctx -c $TPM2_RH_ENDORSEMENT

tpm2_activatecredential -c 0x81010002 -C 0x81010001 -P abc123 -E session:session.ctx -i <filePath> -o <filePath>

tpm2_activatecredential -c ak.dat -C ek.dat -P abc123 -E session:session.ctx -i <filePath> -o <filePath>

tpm2_activatecredential -c 0x81010002 -C 0x81010001 -P 123abc -E session:session.ctx  -i <filePath> -o <filePath>
```

[returns](common/returns.md)

[footer](common/footer.md)
