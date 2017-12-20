% tpm2_certify(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_certify**(1) - prove that an object is loaded in the tpm.

# SYNOPSIS

**tpm2_certify** [*OPTIONS*]

# DESCRIPTION

**tpm2_certify**(1) proves that an object with a specific _NAME_ is loaded in the TPM.
By certifying that the object is loaded, the TPM warrants that a public area
with a given _NAME_ is self-consistent and associated with a valid sensitive area.
If a relying party has a public area that has the same _NAME_ as a _NAME_ certified
with this command, then the values in that public area are correct. The object
may be any object that is loaded with TPM2_Load() or TPM2_CreatePrimary().
An object that only has its public area loaded cannot be certified.

# OPTIONS

These options control the ceritifcation:

  * **-H**, **--obj-handle**=_OBJECT\_HANDLE_:
    The handle of the object to be certified.

  * **-C**, **--obj-context**=_FILE_:
    Use _FILE_ for providing the object context.

  * **-k**, **--key-handle**=_KEY\_HANDLE_:
    Handle of the key used to sign the attestation  structure.

  * **-c**, **--key-context**=_KEY\_CONTEXT_:
    Filename of the key context used to sign the  attestation structure.

  * **-P**, **--pwdo**=_OBJECT\_PASSWORD_:
    Use _OBJECT\_PASSWORD_ for providing an authorization value for the object specified
    in _OBJECT\_HANDLE_.
    Passwords should follow the "password formatting standards, see section
    "Password Formatting".

  * **-K**, **--pwdk**=_KEY\_PASSWORD_:
    Use _KEY_PASSWORD_ for providing an authorization value for the key specified
    in _KEY\_HANDLE_.
    Follows the same formatting guidelines as the object handle password or
    -P option.

  * **-g**, **\--halg**=_HASH\_ALGORITHM_:
    The hash algorithm to use.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-a**, **--attest-file**=_ATTEST\_FILE_:
    Output file name for the attestation data.

  * **-s**, **--sig-file**=_SIG\_FILE_:
    Output file name for the signature data.

  * **-f**, **--format**

    Format selection for the signature output file. See section "Signature Format Specifiers".

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[signature format specifiers](common/signature.md)

# EXAMPLES

```
tpm2_certify -H 0x81010002 -k 0x81010001 -P 0x0011 -K 0x00FF -g 0x00B -a <fileName> -s <fileName>
tpm2_certify -C obj.context -c key.context -P 0x0011 -K 0x00FF -g 0x00B -a <fileName> -s <fileName>
tpm2_certify -H 0x81010002 -k 0x81010001 -P 0011 -K 00FF -g 0x00B -a <fileName> -s <fileName>
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
