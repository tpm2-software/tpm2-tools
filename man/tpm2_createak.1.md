% tpm2_createak(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_createak**(1) - Generate attestation key with given algorithm under the
endorsement hierarchy.

# SYNOPSIS

**tpm2_createak** [*OPTIONS*]

# DESCRIPTION

**tpm2_createak**(1) - Generate an attestation key (AK) with the given algorithm
under the endorsement hierarchy. The context of the attestation key is specified
via **-c**.

If any password option is missing, assume NULL.

The tool outputs to stdout a YAML representation of the loaded key's name, for example:
```
loaded-key:
  name: 000bac149518baa05540a0678bd9b624f8a98d042e46c60f4d098ba394d36fc49268
```

# OPTIONS

  * **-e**, **\--auth-endorse**=_ENDORSE\_AUTH_:

    Specifies current endorsement hierarchy authorization.
    Authorizations should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-P**, **\--auth-ak**=_AK\_AUTH_

    Specifies the attestation key authorization when created.
    Same formatting as the endorse authorization value or **-e** option.

  * **-C**, **\--ek-context**=_EK\_CONTEXT\_OBJECT_:

    Specifies the object context of the endorsement key. Either a file or a handle number.
    See section "Context Object Format".

  * **-c**, **\--context**=_CONTEXT\_FILE\_NAME_:

    Specifies a file path to save the context of the attestation key.

  * **-G**, **\--algorithm**=_ALGORITHM_:

    Specifies the algorithm type of AK. Supports:
    * ecc - An P256 key.
    * rsa - An RSA2048 key.
    * keyedhash - hmac key.

  * **-D**, **\--digest-alg**=_HASH\_ALGORITHM_:

    Like **-G**, but specifies the digest algorithm used for signing.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers". See section "Supported Hash Algorithms"
    for a list of supported hash algorithms.

  * **-s**, **\--sign-alg**=_SIGN\_ALGORITHM_:

    Like **-G** but specifies signing algorithm. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    See section "Supported Signing Algorithms" for a list of supported
    signing algorithms.

  * **-p**, **\--file**=_FILE_:

    Specifies the file used to save the public portion of AK. This will be a
    binary data structure corresponding to the **TPM2B_PUBLIC** struct in the
    specification. One can control the output to other formats via the
    **\--format** option.

  * **-n**, **\--ak-name**=_NAME_:

    Specifies the file used to save the ak name, optional.

  * **-r**, **\--privfile**=_OUTPUT\_PRIVATE\_FILE_:

    The output file which contains the sensitive portion of the object, optional.

[pubkey options](common/pubkey.md)

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[context object format](common/ctxobj.md)

[supported signing algorithms](common/sign-alg.md)

[supported public object algorithms](common/object-alg.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

### Create an Attestation Key and make it persistent

```
tpm2_createek -c ek.handle -G rsa -p ek.pub
tpm2_createak -C ek.handle -c ak.ctx -p ak.pub -n ak.name
tpm2_evictcontrol -c 0x81010002 -o ak.ctx
```

[returns](common/returns.md)

[footer](common/footer.md)
