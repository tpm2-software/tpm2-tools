% tpm2_encryptdecrypt(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption.

# SYNOPSIS

**tpm2_encryptdecrypt** [*OPTIONS*]

# DESCRIPTION

**tpm2_encryptdecrypt**(1) - Performs symmetric encryption or decryption with a
specified symmetric key.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    Name of the key context object to be used for the  operation. Either a file
    or a handle number. See section "Context Object Format".

  * **-p**, **\--auth-key**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-c**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-D**, **\--decrypt**:

    Perform a decrypt operation. Default is encryption.

  * **-i**, **\--in-file**=_INPUT\_FILE_:

    Optional. Specifies the input file path for either the encrypted or decrypted
    data, depending on option **-D**. If not specified, defaults to **stdin**.

  * **-o**, **\--out-file**=_OUT\_FILE_:

    Optional. Specifies the output file path for either the encrypted or decrypted
    data, depending on option **-D**. If not specified, defaults to **stdout**.

  * **-G**, **\--mode**=_CIPHER\_MODE\_ALGORITHM_:

    The key algorithm associated with this object. It defaults to the object's
    mode or CFB if left unconfigured.

    It accepts friendly names just like **-g** option.
    See section "Supported Public Object Algorithms" for a list
    of supported object algorithms.

  * **-t**, **\--iv**=_IV\_INPUT\_FILE_ : _IV\_OUTPUT\_FILE_:

    Optional. The initialization vector to use. Defaults to 0's. The specification
  syntax allows for an input file and output file source to be specified. The input file
  path is first, optionally followed by a colon ":" and the output iv path. This the output
  iv can be saved for subsequent calls when chaining.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported public object algorithms](common/object-alg.md)

# EXAMPLES

```
tpm2_encryptdecrypt -C 0x81010001 -p abc123 -i <filePath> -o <filePath>
tpm2_encryptdecrypt -C key.dat -p abc123 -i <filePath> -o <filePath>
tpm2_encryptdecrypt -C 0x81010001 -p 123abca  -i <filePath> -o <filePath>
```

[returns](common/returns.md)

[footer](common/footer.md)
