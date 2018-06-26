% tpm2_create(1) tpm2-tools | General Commands Manual
%
% AUGUST 2017

# NAME

**tpm2_create**(1) - create an object that can be loaded into a TPM using tpm2_load.
The object will need to be loaded before it may be used.

# SYNOPSIS

**tpm2_create** [*OPTIONS*]

# DESCRIPTION

**tpm2_create**(1) - create an object that can be loaded into a TPM using tpm2_load.
The object will need to be loaded before it may be used.

# OPTIONS

These options for creating the tpm entity:

  * **-C**, **--context-parent**=_PARENT\_CONTEXT\_OBJECT_:
    Context object for the created object's parent. Either a file or a handle
    number. See section "Context Object Format".

  * **-P**, **--auth-parent**=_PARENT\_KEY\_AUTH_:
    The authorization value for using the parent key, optional.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-k**, **--auth-key**=_KEY\_AUTH_:
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
    of supported object algorithms. Mutually exclusive of **-I**.

  * **-A**, **--object-attributes**=_ATTRIBUTES_:
    The object attributes, optional. Object attributes follow the specifications
    as outlined in "object attribute specifiers". The default for created objects is:

    `TPMA_OBJECT_SIGN_ENCRYPT|TPMA_OBJECT_DECRYPT|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH`

    When **-I** is specified for sealing, `TPMA_OBJECT_SIGN_ENCRYPT` and `TPMA_OBJECT_DECRYPT` are removed from the default attribute set.
    The algorithm is set in a way where the the object is only good for sealing and unsealing. Ie one cannot use an object for sealing and cryptography
    operations.

  * **-I**, **--in-file**=_FILE_:
    The data file to be sealed, optional. If file is -, read from stdin.
    When sealing data only the _TPM_ALG_KEYEDHASH_ algorithm with a NULL scheme is allowed. Thus, **-G** cannot
    be specified.

  * **-L**, **--policy-file**=_POLICY\_FILE_:
    The input policy file, optional.

  * **-u**, **--pubfile**=_OUTPUT\_PUBLIC\_FILE_:
    The output file which contains the public portion of the created object, optional.

  * **-r**, **--privfile**=_OUTPUT\_PRIVATE\_FILE_:
    The output file which contains the sensitive portion of the object, optional.

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option. This session
    is used in lieu of starting a session and using the PCR policy options.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](commmon/ctxobj.md)

[authorization formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

[object attribute specifiers](common/object-attrs.md)

# EXAMPLES

```
tpm2_create -C 0x81010001 -P abc123 -K def456 -g sha256 -G keyedhash-I data.File -o opu.File
tpm2_create -C file:parent.context -P abc123 -K def456 -g sha256 -G keyedhash -I data.File -o opu.File
tpm2_create -C 0x81010001 -P 123abc -K 456def -X -g sha256 -G keyedhash -I data.File -o opu.File
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
