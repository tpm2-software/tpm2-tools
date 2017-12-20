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

  * **-H**, **--parent**=_PARENT\_HANDLE_:
    The handle of the parent object to create this object under.

  * **-c**, **--context-parent**=_PARENT\_CONTEXT\_FILE_:
    The filename for parent context.

  * **-P**, **--pwdp**=_PARENT\_KEY\_PASSWORD_:
    The password for parent key, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-K**, **--pwdk**=_KEY\_PASSWORD_:
    The password for key, optional. Follows the password formatting of the
    "password for parent key" option: -P.

  * **-g**, **--halg**=_ALGORITHM_:
    The hash algorithm to use. Algorithms should follow the
    " formatting standards, see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * **-G**, **--kalg**=_KEY\_ALGORITHM_:
    The algorithm associated with this object. It accepts friendly names just
    like -g option. See section "Supported Public Object Algorithms" for a list
    of supported object algorithms.

  * **-A**, **--object-attributes**=_ATTRIBUTES_:
    The object attributes, optional. Object attribytes follow the specifications
    as outlined in "object attribute specifiers". The default for created objects is:

    `TPMA_OBJECT_SIGN|TPMA_OBJECT_FIXEDTPM|TPMA_OBJECT_FIXEDPARENT|TPMA_OBJECT_SENSITIVEDATAORIGIN|TPMA_OBJECT_USERWITHAUTH`

  * **-I**, **--in-file**=_FILE_:
    The data file to be sealed, optional. If file is -, read from stdin.
    When sealing data only the TPM_ALG_KEYEDHASH algorithm is allowed.

  * **-L**, **--policy-file**=_POLICY\_FILE_:
    The input policy file, optional.

  * **-u**, **--pubfile**=_OUTPUT\_PUBLIC\_FILE_:
    The output file which contains the public portion of the created object, optional.

  * **-r**, **--privfile**=_OUTPUT\_PRIVATE\_FILE_:
    The output file which contains the sensitive portion of the object, optional.

* **-S**, **--input-session-handle**=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

[object attribute specifiers](common/obj-attrs.md)

# EXAMPLES

```
tpm2_create -H 0x81010001 -P abc123 -K def456 -g sha256 -G keyedhash-I data.File
tpm2_create -c parent.context -P abc123 -K def456 -g sha256 -G keyedhash -I data.File
tpm2_create -H 0x81010001 -P 123abc -K 456def -g sha256 -G keyedhash -I data.File
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
