% tpm2_create(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_create**(1) - Create a child object.

# SYNOPSIS

**tpm2_create** [*OPTIONS*]

# DESCRIPTION

**tpm2_create**(1) - Create a child object. The object can either be a key or
a sealing object. A sealing object allows to seal user data to the TPM, with a
maximum size of 128 bytes. Additionally it will load the created object if the
**-c** is specified.

# OPTIONS

These options for creating the TPM entity:

  * **-C**, **\--parent-context**=_OBJECT_:

    The parent of the object to be created.

  * **-P**, **\--parent-auth**=_AUTH_:

    The authorization value of the parent object specified with **-C**.

  * **-p**, **\--key-auth**=_AUTH_:

    The authorization value for the created object.

  * **-g**, **\--hash-algorithm**=_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to sha256 when not specified.

  * **-G**, **\--key-algorithm**=_ALGORITHM_:

    The key algorithm associated with this object. It defaults to "rsa" if not
    specified.

  * **-a**, **\--attributes**=_ATTRIBUTES_:

    The object attributes, optional. The default for created objects is:

    `TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|
     TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|
     TPMA_OBJECT_USERWITHAUTH`

    When **-i** is specified for sealing, `TPMA_OBJECT_SIGN_ENCRYPT` and
    `TPMA_OBJECT_DECRYPT` are removed from the default attribute set.
    The algorithm is set in a way where the the object is only good for sealing
    and unsealing. I.e. one cannot use an object for sealing and cryptography
    operations.

    When **-L** is specified for adding policy based authorization information
    AND no string password is specified, the  attribute `TPMA_OBJECT_USERWITHAUTH`
    is cleared unless an explicit choice is made by setting of the attribute
    with **-a** option. This prevents creation of objects with inadvertent auth
    model where in user intended to enforce a policy but inadvertently created
    an object with empty auth which can be used instead of policy authorization.

  * **-i**, **\--sealing-input**=_FILE_ or _STDIN_:

    The data file to be sealed, optional. If file is -, read from stdin.
    When sealing data only the _TPM\_ALG\_KEYEDHASH_ algorithm with a NULL
    scheme is allowed. Thus, **-G** cannot be specified.

  * **-L**, **\--policy**=_FILE_ or _HEX\_STRING_:

    The input policy file or a hex string, optional.

  * **-u**, **\--public**=_FILE_:

    The output file which contains the public portion of the created object,
    optional.

  * **-r**, **\--private**=_FILE_:

    The output file which contains the sensitive portion of the object,
    optional.
    [protection details](common/protection-details.md)


  * **-c**, **\--key-context**=_FILE_:

    The output file which contains the key context, optional. The key context is
    analogous to the context file produced by **tpm2_load**(1), however is
    generated via a **tpm2_createloaded**(1) command. This option can be used to
    avoid the normal **tpm2_create**(1) and **tpm2_load**(1) command sequences
    and do it all in one command, atomically.

  * **\--creation-data**=_FILE_:

    An optional file output that saves the creation data for certification.

    * **\--template-data**=_FILE_:

    An optional file output that saves the key template data (TPM2B_PUBLIC) to
    be used in **tpm2_policytemplate**.

  * **-t**, **\--creation-ticket**=_FILE_:

    An optional file output that saves the creation ticket for certification.

  * **-d**, **\--creation-hash**=_FILE_:

    An optional file output that saves the creation hash for certification.

  * **-q**, **\--outside-info**=_HEX\_STR\_OR\_FILE_:

    An optional hex string or path to add unique data to the creation data.
    Note that it does not contribute in creating statistically unique object.

  * **-l**, **\--pcr-list**=_PCR_:

    The list of PCR banks and selected PCRs' ids for each bank to be included in
    the creation data for certification.

  * **\--cphash**=_FILE_

    File path to record the hash of the command parameters. This is commonly
    termed as cpHash. NOTE: When this option is selected, The tool will not
    actually execute the command, it simply returns a cpHash.

* **\--rphash**=_FILE_

     File path to record the hash of the response parameters. This is commonly
     termed as rpHash.

  * **-S**, **\--session**=_FILE_:

    The session created using **tpm2_startauthsession**. Multiple of these can
    be specified. For example, you can have one session for auditing and another
    for encryption/decryption of the parameters.

[pubkey options](common/pubkey.md)

    Public key format.

  * **-o**, **\--output**=_FILE_:

    The output file path, recording the public portion of the object.

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

## Setup

In order to create an object, we must first create a primary key as it's parent.
```bash
tpm2_createprimary -c primary.ctx
```

## Create an Object

This will create an object using all the default values and store the TPM sealed
private and public portions to the paths specified via -u and -r respectively.
The tool defaults to an RSA key.

```bash
tpm2_create -C primary.ctx -u obj.pub -r obj.priv
```

## Seal Data to the TPM

Outside of key objects, the TPM allows for small amounts of user specified data
to be sealed to the TPM.

```bash
echo "my sealed data" > seal.dat
tpm2_create -C primary.ctx -i seal.dat -u obj.pub -r obj.priv
```

## Create an EC Key Object and Load it to the TPM

Normally, when creating an object, only the public and private portions of the
object are returned and the caller needs to use tpm2\_load(1) to load those
public and private portions to the TPM before being able to use the object.
However, this can be accomplished within this command as well, when supported
by the TPM. You can verify your TPM supports this feature by checking
that tpm2\_getcap(1) commands returns TPM2\_CC\_CreateLoaded in the command set.
If your TPM does not support TPM2\_CC\_CreateLoaded an unsuported command code
error will be returned. If it's not supported one must use tpm2\_load(1). See
that manpage for details on its usage.

```bash
tpm2_create -C primary.ctx -G ecc -u obj.pub -r obj.priv -c ecc.ctx
```

## Create an Object and get the public key as a PEM file

This will create an object using all the default values but also output the
public key as a PEM file compatible with tools like OpenSSL and whatever supports
PEM files.

```bash
tpm2_create -C primary.ctx -u obj.pub -r obj.priv -f pem -o obj.pem
```
## Create a restricted RSA signing key

For a restricted signing key the scheme and null for the symmetric algorithm must be
specified.

```bash
tpm2_create -C primary.ctx -Grsa2048:rsapss:null  \
    -a "fixedtpm|fixedparen|sensitivedataorigin|userwithauth|restricted|sign" \
    -r obj.priv -u obj.pub
```

[returns](common/returns.md)

[footer](common/footer.md)
