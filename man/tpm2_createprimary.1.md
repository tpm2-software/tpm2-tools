% tpm2_createprimary(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_createprimary**(1) - Create a primary key.

# SYNOPSIS

**tpm2_createprimary** [*OPTIONS*]

# DESCRIPTION

**tpm2_createprimary**(1) - This command is used to create a primary object
under one of the hierarchies: Owner, Platform, Endorsement, NULL. The command
will create and load a Primary Object. The sensitive and public portions are not
returned. A context file for the created object's handle is saved as a file for
future interactions with the created primary.

# OPTIONS

  * **-C**, **\--hierarchy**=_OBJECT_:

    The hierarchy under which the object is created. This will also dictate
    which authorization secret (if any) must be supplied. Defaults to
    **TPM_RH_OWNER**, when no value specified.
    Supported options are:
      * **o** for **TPM_RH_OWNER**
      * **p** for **TPM_RH_PLATFORM**
      * **e** for **TPM_RH_ENDORSEMENT**
      * **n** for **TPM_RH_NULL**
      * **`<num>`** where a raw number can be used.

  * **-P**, **\--hierarchy-auth**=_AUTH_:

    The authorization value for the hierarchy specified with **-C**.

  * **-p**, **\--key-auth**=_AUTH_:

    The authorization value for the primary object created.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm to use for generating the objects name.
    Defaults to sha256 if not specified.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The algorithm type for the generated primary key. Defaults to
    rsa2048:null:aes128cfb.

  * **-c**, **\--key-context**=_FILE_:

    The file path to save the object context of the generated primary object.

  * **-L**, **\--policy**=_FILE_:

    An optional file input that contains the policy digest for policy based
    authorization of the object.

  * **-a**, **\--attributes**=_ATTRIBUTES_:

    The object attributes, optional. Defaults to:
    `TPMA_OBJECT_RESTRICTED|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|
     TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|
     TPMA_OBJECT_USERWITHAUTH`

  * **-u**, **\--unique-data**=_FILE_:

    An optional file input that contains the unique field of **TPMT_PUBLIC** in
    little-endian format.

  * **\--creation-data**=_FILE_:

    An optional file output that saves the creation data for certification.

  * **-t**, **\--creation-ticket**=_FILE_:

    An optional file output that saves the creation ticket for certification.

  * **-d**, **\--creation-hash**=_FILE_:

    An optional file output that saves the creation hash for certification.

## References

[context object format](common/ctxobj.md) details the methods for specifying
_OBJECT_.

[authorization formatting](common/authorizations.md) details the methods for
specifying _AUTH_.

[algorithm specifiers](common/alg.md) details the options for specifying
cryptographic algorithms _ALGORITHM_.

[object attribute specifiers](common/obj-attrs.md) details the options for
specifying the object attributes _ATTRIBUTES_.

[common options](common/options.md) collection of common options that provide
information many users may expect.

[common tcti options](common/tcti.md) collection of options used to configure
the various known TCTI modules.


# EXAMPLES

## Create an ECC primary object
```bash
tpm2_createprimary -C o -g sha256 -G ecc -c context.out
```

## Create a primary object that follows the guidance of TCG Provisioning guide

See : https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf

Where unique.dat contains the binary-formatted data: 0x00 0x01 (0x00 * 256)

```bash
tpm2_createprimary -C o -G rsa2048:aes128cfb -g sha256 -c prim.ctx \
-a 'restricted|decrypt|fixedtpm|fixedparent|sensitivedataorigin|userwithauth|\
noda' -u unique.dat
```

[returns](common/returns.md)

[footer](common/footer.md)
