# Authorization Formatting

Authorization for use of an object in TPM2.0 can come in 3 different forms:
1. Password
2. HMAC
3. Sessions

**NOTE:** "Authorizations default to the **EMPTY PASSWORD** when not specified".

## Passwords

Passwords are interpreted in three forms; string, hex-string or a file. A string password is not
interpreted, and is directly used for authorization. A hex-string password is converted from
a hexidecimal form into a byte array form, thus allowing passwords with non-printable
and/or terminal un-friendly characters.
A file form should be the path of a file containing a password in string or hex-string format to be read by the tool.
Storing passwords in files prevents information leakage, passwords passed as options can be read from the process list.

By default passwords are assumed to be in the string form. Password form is specified
with special prefix values, they are:

  * str: - Used to indicate it is a raw string. Useful for escaping a password that starts
         with the "hex:" prefix.
  * hex: - Used when specifying a password in hex string format.
  * file: - Used when specifying a password stored in a file. Useful to prevent leaking the
         password to UNIX utilities (such as ps).

## HMAC

HMAC tickets can be presented as hex escaped passwords.

## Sessions

When using a policy session to authorize the use of an object, prefix the option argument
with the *session* keyword.  Then indicate a path to a session file that was created
with tpm2_startauthsession(1). Optionally, if the session requires an auth value to be
sent with the session handle (eg policy password), then append a + and a string as described
in the **Passwords** section.

### Examples

To satisfy a PCR policy of sha256 on banks 0, 1, 2 and 3 use a specifier of:
```
pcr:sha256:0,1,2,3
```

To use a session context file called *session.ctx*.
```
session:session.ctx
```

To use a session context file called *session.ctx* **AND** send the authvalue mypassword.
```
session:session.ctx+mypassword
```

To use a session context file called *session.ctx* **AND** send the *HEX* authvalue 0x11223344.
```
session:session.ctx+hex:11223344
```
