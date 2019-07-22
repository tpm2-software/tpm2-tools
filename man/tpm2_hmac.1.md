% tpm2_hmac(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_hmac**(1) - Performs an HMAC operation with the TPM.

# SYNOPSIS

**tpm2_hmac** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_hmac**(1) - Performs an HMAC operation on _FILE_ and returns the results. If
_FILE_ is not specified, then data is read from stdin.

The hashing algorithm defaults to the keys scheme or sha256 if the key has a NULL scheme.

Output defaults to *stdout* and binary format unless otherwise specified via **-o**
and **--hex** options respectively.

# OPTIONS

  * **-c**, **\--key-context**=_KEY\_CONTEXT\_OBJECT_:

    The context object of the symmetric signing key providing the HMAC key.
    Either a file or a handle number. See section "Context Object Format".

  * **-p**, **\--auth**=_KEY\_AUTH_:

    Optional authorization value to use the key specified by **-C**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-g**, **\--hash-algorithm**=_HASH\_ALGORITHM_:

    The hash algorithm to use.
    Algorithms should follow the "formatting standards", see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **\--hex**

	Convert the output hmac to hex format without a leading "0x".

  * **-o**, **\--output**=_OUT\_FILE_

    Optional file record of the HMAC result. Defaults to stdout.

  * **-t**, **\--ticket**=_TICKET\_FILE_

    Optional file record of the ticket result.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

## Setup
```
# create a primary object
tpm2_createprimary -o primary.ctx

# create an hmac key
tpm2_create -C primary.ctx -Ghmac -o hmac.key
```

### Perform an HMAC with Default Hash Algorithm
Perform an hmac using the key's default scheme (hash algorithm) and
output to stdout in hexidecimal format.

```
tpm2_hmac -c hmac.key --hex data.in
e6eda48a53a9ddbb92f788f6d98e0372d63a408afb11aca43f522a2475a32805
```

[returns](common/returns.md)

[footer](common/footer.md)
