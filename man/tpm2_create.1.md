% tpm2_create(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_create**(1) - Create an object that can be loaded into a TPM using **tpm2_load**.
The object will need to be loaded before it may be used.

# SYNOPSIS

**tpm2_create** [*OPTIONS*]

# DESCRIPTION

**tpm2_create**(1) - Create an object that can be loaded into a TPM using **tpm2_load**.
The object will need to be loaded before it may be used.

# OPTIONS

These options for creating the TPM entity:

  * **-C**, **--context-parent**=_PARENT\_CONTEXT\_OBJECT_:

    Context object for the created object's parent. Either a file or a handle
    number. See section "Context Object Format".

  * **-P**, **--auth-parent**=_PARENT\_KEY\_AUTH_:

    The authorization value for using the parent key, optional.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-p**, **--auth-key**=_KEY\_AUTH_:

    The authorization value for the key, optional.
    Follows the authorization formatting of the
    "password for parent key" option: **-P**.

  * **-g**, **--halg**=_ALGORITHM_:

    The hash algorithm for generating the objects name. This is optional
    and defaults to sha256 when not specified. Algorithms should follow the
    "formatting standards", see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-G**, **--kalg**=_KEY\_ALGORITHM_:

    The key algorithm associated with this object. It defaults to "rsa" if not
    specified.
    It accepts friendly names just like -g option.
    See section "Supported Public Object Algorithms" for a list
    of supported object algorithms. Mutually exclusive of **-i**.

  * **-b**, **--object-attributes**=_ATTRIBUTES_:

    The object attributes, optional. Object attributes follow the specifications
    as outlined in "object attribute specifiers". The default for created objects is:

    `TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH`

    When **-i** is specified for sealing, `TPMA_OBJECT_SIGN_ENCRYPT` and `TPMA_OBJECT_DECRYPT`
    are removed from the default attribute set.
    The algorithm is set in a way where the the object is only good for sealing and unsealing.
    I.e. one cannot use an object for sealing and cryptography
    operations.

  * **-i**, **--in-file**=_FILE_:

    The data file to be sealed, optional. If file is -, read from stdin.
    When sealing data only the _TPM\_ALG\_KEYEDHASH_ algorithm with a NULL scheme is allowed.
    Thus, **-G** cannot be specified.

  * **-L**, **--policy-file**=_POLICY\_FILE_:

    The input policy file, optional.

  * **-u**, **--pubfile**=_OUTPUT\_PUBLIC\_FILE_:

    The output file which contains the public portion of the created object, optional.

  * **-r**, **--privfile**=_OUTPUT\_PRIVATE\_FILE_:

    The output file which contains the sensitive portion of the object, optional.

  * **-o**, **--out-context**=_OUTPUT\_CONTEXT\_FILE_:

    The output file which contains the key context, optional. The key context is analogous to the context
    file produced by **tpm2_load**(1), however is generated via a **tpm2_createloaded**(1) command. This option
    can be used to avoid the normal **tpm2_create**(1) and **tpm2_load**(1) command sequences and do it all in one
    command, atomically.


[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

[object attribute specifiers](common/object-attrs.md)

# EXAMPLES

## Create an object whose parent is provided via parent.ctx
```
tpm2_create -C parent.ctx -u obj.pub obj.priv
```

## Create an object and seal data to it
```
tpm2_create -C parent.ctx  -K def456 -G keyedhash -i seal.dat -u obj.pub -r obj.priv
```

## Create an rsa2048 object and load it into the TPM
```
tpm2_create -C primary.ctx -G rsa2048 -u obj.pub -r obj.priv -o obj.ctx
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
