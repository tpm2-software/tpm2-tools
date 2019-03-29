% tpm2_createprimary(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_createprimary**(1) - Create a primary key under a primary seed or a temporary
primary key under the **TPM_RH_NULL** hierarchy.

# SYNOPSIS

**tpm2_createprimary** [*OPTIONS*]

# DESCRIPTION

**tpm2_createprimary**(1) - This command is used to create a Primary Object under
one of the Primary Seeds or a Temporary Object under **TPM_RH_NULL**. The command
uses a **TPM2B_PUBLIC** as a template for the object to be created. The command
will create and load a Primary Object. The sensitive area is not returned.
A context file for the created object's handle is saved to disk for future
interactions with the created primary.

# OPTIONS

  * **-a**, **--hierarchy**=_HIERARCHY_:

    Specify the hierarchy under which the object is created. This will also
    dictate which authorization secret (if any) must be supplied. Defaults to
    **o**, **TPM_RH_OWNER**, when no value specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **e** for **TPM_RH_ENDORSEMENT**
      * **n** for **TPM_RH_NULL**
      * **`<num>`** where a raw number can be used.

  * **-P**, **--auth-hierarchy**=_HIERARCHY\_\_AUTH\_VALUE_:

    Optional authorization value when authorization is required to create object
    under the specified hierarchy given via the **-a** option. Authorization
    values should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-p**, **--auth-object**=_OBJECT\_AUTH_:

    Optional authorization password for the newly created object. Password
    values should follow the "authorization formatting standards", see section
    "Authorization Formatting".

  * **-g**, **--halg**=_ALGORITHM_:

    The hash algorithm to use for generating the objects name.
    If not specified, the default name algorithm is SHA256.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers". Also, see section
    "Supported Hash Algorithms" for a list of supported hash algorithms.

  * **-G**, **--kalg**=_KEY\_ALGORITHM_:

    Algorithm type for generated key. If not specified, the default key
    algorithm is RSA. See section "Supported Public Object Algorithms"
    for a list of supported object algorithms.

  * **-o**, **--out-context-name**=_CONTEXT\_FILE\_NAME_:

    Optional file name to use for the returned object context, otherwise a
    default of _primary.ctx_ is used.

  * **-L**, **--policy-file**=_POLICY\_FILE_:

    An optional file input that contains the policy digest for policy based authorization of the object.

  * **-A**, **--object-attributes**=_ATTRIBUTES_:

    The object attributes, optional. Object attributes follow the specifications
    as outlined in "object attribute specifiers". The default for created objects is:

    `TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH`

  * **-u**, **--unique-data**=_UNIQUE\_FILE_:

    An optional file input that contains the binary bits of a **TPMU_PUBLIC_ID** union where
    numbers (such as length words) are in little-endian format. This is passed in the
    unique field of **TPMT_PUBLIC**.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

[object attribute specifiers](common/object-attrs.md)

# EXAMPLES

## Create an ECC primary object
```
tpm2_createprimary -a o -g sha256 -G ecc -o context.out
```

## Create a primary object that follows the guidance of TCG Provisioning guide

See : https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf

Where unique.dat contains the binary-formatted data: 0x00 0x01 (0x00 * 256)

```
tpm2_createprimary -a o -G rsa2048:aes128cfb -g sha256 -o prim.ctx \
  -A 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|noda' \
  -u unique.dat
```


# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
