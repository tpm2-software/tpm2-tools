% tpm2_hmac(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_hmac**(1) - Performs an HMAC operation with the TPM.

# SYNOPSIS

**tpm2_hmac** [*OPTIONS*] _FILE_

# DESCRIPTION

**tpm2_hmac**(1) - performs an HMAC operation on _FILE_ and returns the results. If
_FILE_ is not specified, then data is read from stdin.

# OPTIONS

 * **-k**, **--key-handle**=_KEY\_CONTEXT\_FILE_:
    The key handle for the symmetric signing key providing the HMAC key.

  * **-c**, **--key-context**=_KEY\_CONTEXT\_FILE_:
    The filename of the key context used for the operation.

  * **-P**, **--pwdk**=_KEY\_PASSWORD_:
    The password for key, optional. Passwords should follow the
    "password formatting standards, see section "Password Formatting".

  * **-g**, **--halg**=_HASH\_ALGORITHM_:
    The hash algorithm to use.
    Algorithms should follow the "formatting standards, see section
    "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported hash
    algorithms.

  * **-o**, **--out-file**=_OUT\_FILE_
    Optional file record of the HMAC result. Defaults to stdout.

  * **-S**, **--session**=_SESSION\_FILE_:

    Optional, A session file from **tpm2_startauthsession**(1)'s **-S** option.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

Perform a SHA1 HMAC on data.in and send output and possibly ticket to stdout:

```
tpm2_hmac -k 0x81010002 -P abc123 -g sha1 data.in
```

Perform a SHA1 HMAC on data.in read as a file to stdin and send output to a file:
```
tpm2_hmac -c key.context -P abc123 -g sha1 -o hash.out << data.in
```
Perform a SHA256 HMAC on _stdin_ and send result and possibly ticket to stdout:

```
cat data.in | tpm2_hmac -k 0x81010002 -g sha256 -o hash.out
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
