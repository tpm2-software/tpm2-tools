% tpm2_load(1) tpm2-tools | General Commands Manual
%
% SEPTEMBER 2017

# NAME

**tpm2_load**(1) - Load an object into the TPM.

# SYNOPSIS

**tpm2_load** [*OPTIONS*]

# DESCRIPTION

**tpm2_load**(1) - Load both the private and public portions of an object
into the TPM.
The tool outputs the name of the loaded object in a YAML format and saves a
context file for future interactions with the object.

# OPTIONS

  * **-C**, **\--context-parent**=_PARENT\_CONTEXT\_OBJECT_:

    Context object loaded object's parent. Either a file or a handle number.
    See section "Context Object Format".

  * **-P**, **\--auth-parent**=_KEY\_AUTH_:

    Optional authorization value to use the parent object specified by **-C**.
    Authorization values should follow the "authorization formatting standards",
    see section "Authorization Formatting".

  * **-u**, **\--pubfile**=_PUBLIC\_OBJECT\_DATA\_FILE_:

    A file containing the public portion of the object.

  * **-r**, **\--privfile**=_PRIVATE\_OBJECT\_DATA\_FILE_:

    A file containing the sensitive portion of the object.

  * **-n**, **\--name**=_NAME\_DATA\_FILE_:

    An optional file to save the name structure of the object.

  * **-o**, **\--out-context**=_CONTEXT\_FILE\_NAME_:

    The file name of the saved object context, required.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[context object format](common/ctxobj.md)

[authorization formatting](common/authorizations.md)


# EXAMPLES

```
tpm2_load  -C parent.ctx -P abc123 -u <pubKeyFileName> -r <privKeyFileName> -n <outPutFileName> -o object.context

tpm2_load  -C parent.ctx -P "hex:123abc" -u <pubKeyFileName> -r <privKeyFileName> -n <outPutFileName>

```

[returns](common/returns.md)

[footer](common/footer.md)
