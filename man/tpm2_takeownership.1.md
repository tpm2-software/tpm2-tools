tpm2_takeownership 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_takeownership(1) - Insert authorization values for the owner, endorsement
and lockout authorizations.

SYNOPSIS
--------

`tpm2_takeownership` [OPTIONS]

DESCRIPTION
-----------

tpm2_takeownership(1) - performs a hash operation on _FILE_ and returns the results. If
_FILE_ is not specified, then data is read from stdin. If the results of the
hash will be used in a signing operation that uses a restricted signing key,
then the ticket returned by this command can indicate that the hash is safe to
sign.

OPTIONS
-------

  * `-o`, `--ownerPassword`=_OWNER\_PASSWORD_:
    The new owner authorization value.

    Passwords should follow the password formatting standards, see section
    "Password Formatting".

  * `-e`, `--endorsePassword`=_ENDORSE\_PASSWORD_:

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * `-l`, `--lockoutPassword`=_LOCKOUT\_PASSWORD_:

    The new lockout authorization value.

    The new endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * `-O`, `--oldOwnerPassword`=_OLD\_OWNER\_PASSWORD_:

    The old owner authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * `-E`, `--oldEndorsePassword`=_OLD\_ENDORSE\_PASSWORD_:

    The old endorse authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * `-L`, `--oldLockoutPassword`=_OLD\_LOCKOUT\_PASSWORD_:

    The old lockout authorization value. Passwords should follow the same
    formatting requirements as the -o option.

  * `-c`, `--clear`:

    Clears the 3 authorizations values with  lockout auth, thus one must specify
    -L.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

EXAMPLES
--------

Set owner, endorsement and lockout authorizations to an empty auth value:

```
tpm2_takeownership -c -L oldlockoutpasswd
```

Set owner, endorsement and lockout authorizations to a new value:

```
tpm2_takeownership -o newo -e newe -l newl -O oldo -E olde -L oldl
```

RETURNS
-------
0 on success or 1 on failure.

BUGS
----
[Github Issues](https://github.com/01org/tpm2-tools/issues)

HELP
----
See the [Mailing List](https://lists.01.org/mailman/listinfo/tpm2)