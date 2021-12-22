% tpm2_createak(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_createak**(1) - Generate attestation key with given algorithm under the
endorsement hierarchy.

# SYNOPSIS

**tpm2_createak** [*OPTIONS*]

# DESCRIPTION

**tpm2_createak**(1) - Generate an attestation key (AK) with the given algorithm
under the endorsement hierarchy. The context of the attestation key is specified
via **-c**.

The tool outputs to stdout a YAML representation of the loaded key's name, for
example:
```
loaded-key:
  name: 000bac149518baa05540a0678bd9b624f8a98d042e46c60f4d098ba394d36fc49268
```

# OPTIONS

  * **-P**, **\--eh-auth**=_AUTH_:

    The authorization value for the endorsement hierarchy.

  * **-p**, **\--ak-auth**=_AUTH_

    The authorization value for the attestation key object created.

  * **-C**, **\--ek-context**=_OBJECT_:

    The endorsement key object.

  * **-c**, **\--ak-context**=_FILE_:

    The file path to save the object context of the attestation key.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    Specifies the attestation key algorithm. Supports:
    * **ecc** - A NIST_P256 key by default. Alternative curves can be selected
      using algorithm specifiers (e.g. **ecc384** or **ecc_nist_p384**) .
    * **rsa** - An RSA2048 key.
    * **keyedhash** - hmac key.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    Specifies the digest algorithm used for signing.

  * **-s**, **\--signing-algorithm**=_ALGORITHM_:

    The signing algorithm.

  * **-u**, **\--public**=_FILE_:

    The file to save the public portion of the attestation key.

  * **-n**, **\--ak-name**=_FILE_:

    The file to save the attestation key name, optional.

  * **-r**, **\--private**=_FILE_:

    The output file which contains the sensitive portion of the object, optional.
    [protection details](common/protection-details.md)

[pubkey options](common/pubkey.md)

    Format selection for the signature output file.

  * **-q**, **\--ak-qualified-name**=_FILE_:

    The qualified name of the attestation key object. The qualified name is the qualified name
    of the parent object (the EK in this instance) and the name of the object itself. Thus, the
    qualified name of an object serves to bind it to its parents.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[signature format specifiers](common/signature.md) option used to configure
signature _FORMAT_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.

# EXAMPLES

### Create an Attestation Key and make it persistent

```bash
tpm2_createek -c ek.handle -G rsa -u ek.pub
tpm2_createak -C ek.handle -c ak.ctx -u ak.pub -n ak.name
tpm2_evictcontrol -C o -c ak.ctx 0x81010002
```

[returns](common/returns.md)

[footer](common/footer.md)
