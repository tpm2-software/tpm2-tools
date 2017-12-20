% tpm2_getpubek(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_getpubek**(1) - Generate TCG profile compliant endorsement key.

# SYNOPSIS

**tpm2_getpubek** [*OPTIONS*]

# DESCRIPTION

**tpm2_getpubek**(1) - Generate TCG profile compliant endorsement key(endorsement
hierarchy primary object), make it persistent with give ek handle, and return
public EK, if any passwd option is missing, assume NULL.

Refer to:
<http://www.trustedcomputinggroup.org/files/static_page_files/7CAA5687-1A4B-B294-D04080D058E86C5F>

# OPTIONS

  * **-e**, **--endorse-passwd**=_ENDORSE\_PASSWORD_:
    Specifies current endorsement password, defaults to NULL.
    Passwords should follow the "password formatting standards, see section
    "Password Formatting".

  * **-o**, **--owner-passwd**=_OWNER\_PASSWORD_
    Specifies the current owner password, defaults to NULL.
    Same formatting as the endorse password value or -e option.

  * **-P**, **--eKPasswd**=_EK\_PASSWORD_
    Specifies the EK password when created, defaults to NULL.
    Same formatting as the endorse password value or -e option.

  * **-H**, **--handle**=_HANDLE_:
    specifies the handle used to make EK  persistent (hex).

  * **-g**, **--algorithm**=_ALGORITHM_:
    specifies the algorithm type of EK.
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms. See section "Algorithm Specifiers" on how to specify
    an algorithm argument.

  * **-f**, **--file**=_FILE_:
    specifies the file used to save the public  portion of EK. This will be a
    binary data structure corresponding to the TPM2B_PUBLIC struct in the
    specification.

  * **-S**, **--input-session-handle**=_SESSION_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

# EXAMPLES

```
tpm2_getpubek -e abc123 -o abc123 -P passwd -H 0x81010001 -g rsa -f ek.pub
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
