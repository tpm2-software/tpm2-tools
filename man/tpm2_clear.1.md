% tpm2_clear(1) tpm2-tools | General Commands Manual

# NAME

**tpm2_clear**(1) - Clears lockout, endorsement and owner hierarchy authorization
values.

# SYNOPSIS

**tpm2_clear** [OPTIONS] _AUTH\_VALUE_

# DESCRIPTION

**tpm2_clear**(1) - Send a clear command to the TPM to clear the 3 hierarchy
authorization values. As an argument takes the auth value for either platform or
lockout hierarchy

**NOTE**: All objects created under the respective hierarchies are lost.

# OPTIONS

  * **-p**, **\--platform**:

    Specifies the tool should operate on the platform hierarchy. By default
    it operates on the lockout hierarchy.

    **NOTE : Operating on platform hierarchy require platform authentication.**

[common options](common/options.md)

[common tcti options](common/tcti.md)

[authorization formatting](common/authorizations.md)

# EXAMPLES

## Set owner, endorsement and lockout authorizations to an empty value

```
tpm2_clear lockoutpasswd
```

## Clear the authorization values on the platform hierarchy
```
tpm2_clear -p
```

[returns](common/returns.md)

[footer](common/footer.md)
