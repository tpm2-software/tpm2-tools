% tss2_changeauth(1) tpm2-tools | General Commands Manual
%
% APRIL 2019

# NAME

**tss2_changeauth**(1) - This command changes the authorization data of an entity referred to by the path.

# SYNOPSIS

**tss2_changeauth** [*OPTIONS*]

[common fapi references](common/tss2-fapi-references.md)

# DESCRIPTION

**tss2_changeauth**(1) -

# OPTIONS

These are the available options:

  * **-a**, **\--authValue**=_STRING_:

    The new UTF-8 password. Optional parameter. If it is neglected then the user
    is queried interactively for a password. To set no password, this option
    should be used with the empty string ("").  The maximum password size is
    determined by the digest size of the chosen name hash algorithm in the
    cryptographic profile (cf., **fapi-profile(5)**). For example, choosing
    SHA256 as hash algorithm, allows passwords of a maximum size of 32
    characters.

  * **-p**, **\--entityPath**=_STRING_:

    The path identifying the entity to modify.

[common tss2 options](common/tss2-options.md)

# EXAMPLES

## Change a password for an entity HS/SRK/myRSACryptKey to M1
```
tss2_changeauth --entityPath=HS/SRK/myRSACryptKey --authValue=M1
```

## Change a password for an entity HS/SRK/myRSACryptKey and ask the user to enter the password.
```
tss2_changeauth --entityPath=HS/SRK/myRSACryptKey
```

# RETURNS

0 on success or 1 on failure.

[footer](common/footer.md)
