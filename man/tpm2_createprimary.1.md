tpm2_createprimary 1 "SEPTEMBER 2017" tpm2-tools
==================================================

NAME
----

tpm2_createprimary(1) - Create a primary key under a primary seed or a temporary
primary key under the `TPM_RH_NULL` hierarchy.

SYNOPSIS
--------

`tpm2_createprimary` [OPTIONS]

DESCRIPTION
-----------

tpm2_createprimary(1) - This command is used to create a Primary Object under
one of the Primary Seeds or a Temporary Object under `TPM_RH_NULL`. The command
uses a `TPM2B_PUBLIC` as a template for the object to be created. The command
will create and load a Primary Object. The sensitive area is not returned.

OPTIONS
-------

  * `-A`, `--auth`=_HIERARCHY_:
    File to save the policy digest.
    Specify the hierarchy under which the object is created. This will also dictate which authorization secret (if any) must be supplied.
    Supported options are:
      * `o` for `TPM_RH_OWNER`
      * `p` for `TPM_RH_PLATFORM`
      * `e` for `TPM_RH_ENDORSEMENT`
      * `n` for `TPM_RH_NULL`

  * `-P`, `--pwdp`=_PARENT\_KEY\_PASSWORD_:
    Optional authorization string if authorization is required to create object under the specified hierarchy.
    Passwords should follow the "password formatting standards, see section "Password Formatting".

  * `-K`, `--pwdk`=_KEY\_PASSWORD_:
    Optional authorization string for the newly created object. Follows the same password formating guidelines
    as the parent authorization string under the -P option.

  * `-g`, `--halg`=_ALGORITHM_:
    The hash algorithm to use. Algorithms should follow the
    " formatting standards, see section "Algorithm Specifiers".
    Also, see section "Supported Hash Algorithms" for a list of supported
    hash algorithms.

  * `-G`, `--kalg`=_KEY\_ALGORITHM_:
    Algorithm type for generated key. It supports friendly names like the -g option.
    See section "Supported Public Object Algorithms" for a list of supported
    object algorithms.

  * `-C`, `--context`=_CONTEXT\_FILE_:
    An optional file used to store the object context returned.

  * `-L`, `--policy-file`=_POLICY\_FILE_:
    An optional file input that contains the policy digest for policy based authorization of the object.

  * `-E`, `--enforce-policy`:
    Option to enforce policy based authorization on the created primary object.

  * `-S`, `--input-session-handle`=_SESSION\_HANDLE_:
    Optional Input session handle from a policy session for authorization.

[common options](common/options.md)

[common tcti options](common/tcti.md)

[password formatting](common/password.md)

[supported hash algorithms](common/hash.md)

[supported public object algorithms](common/object-alg.md)

[algorithm specifiers](common/alg.md)

EXAMPLES
--------
```
tpm2_createprimary -A o -g sha256 -G ecc -C context.out
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

AUTHOR
------
William Roberts <william.c.roberts@intel.com>
