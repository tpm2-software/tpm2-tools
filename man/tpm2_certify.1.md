% tpm2_certify(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_certify**(1) - Prove that an object is loaded in the TPM.

# SYNOPSIS

**tpm2_certify** [*OPTIONS*]

# DESCRIPTION

**tpm2_certify**(1) - Proves that an object with a specific _NAME_ is loaded in the TPM.
By certifying that the object is loaded, the TPM warrants that a public area
with a given _NAME_ is self-consistent and associated with a valid sensitive area.

If a relying party has a public area that has the same _NAME_ as a _NAME_ certified
with this command, then the values in that public area are correct. An object that only has
its public area loaded cannot be certified.

# OPTIONS

These options control the certification:

  * **-c**, **\--certifiedkey-context**=_CERTIFIED\_KEY\_OBJECT\_CONTEXT_:

    Context object for the object to be certified. Either a file or a handle number.
    See section "Context Object Format".

  * **-C**, **\--signingkey-context**=_SIGNING\_KEY\_OBJECT\_CONTEXT_:

    Context object for the key used to sign the attestation structure.
    See section "Context Object Format".

  * **-p**, **\--certifiedkey-auth**=_CERTIFIED\_KEY\OBJECT\_AUTH_:

    Use _CERTIFIED\_KEY\OBJECT\_AUTH_ for providing an authorization value for the object specified
    in _CERTIFIED\_KEY\_OBJECT\_CONTEXT_.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-g**, **\--halg**=_HASH\_ALGORITHM_:

    The hash algorithm to use.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-P**, **\--signingkey-auth**=_SIGNING\_KEY_:

    Use _SIGNING\_KEY_ for providing an authorization value for the key specified
    in _SIGNING\_KEY\_OBJECT\_CONTEXT_.
    Follows the same formatting guidelines as the object handle authorization or
    **-P** option.

  * **-o**, **\--attestation**=_ATTEST\_FILE_:

    Output file name for the attestation data.

  * **-s**, **\--signature**=_SIGNATURE\_FILE_:

    Output file name for the signature data.

  * **-f**, **\--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

```
tpm2_certify -H 0x81010002 -P 0x0011 -p 0x00FF -g 0x00B -a <fileName> -s <fileName>

tpm2_certify -C obj.context -c key.context -P 0x0011 -p 0x00FF -g 0x00B -a <fileName> -s <fileName>

tpm2_certify -H 0x81010002 -P 0011 -p 00FF  -g 0x00B -a <fileName> -s <fileName>
```

[returns](common/returns.md)

[footer](common/footer.md)
