# Authorization Formatting

Authorization for use of an object in TPM2.0 can come in 3 different forms:
1. Password
2. HMAC
3. Sessions

**NOTE:** "Authorizations default to the **EMPTY PASSWORD** when not specified".

## Passwords

Passwords are interpreted in four forms:
1. String
2. Hex-string
3. File
4. Stdin

A string password is not interpreted, and is directly used for authorization. A
hex-string password is converted from a hexidecimal form into a byte array form,
thus allowing passwords with non-printable and/or terminal un-friendly
characters. A file form should be the path of a file containing a password in
string or hex-string format to be read by the tool. Storing passwords in files
prevents information leakage, passwords passed as options can be read from the
process list. Stdin password input, just like string, is not interpreted. When
specifying stdin passwords, there are two ways: Prompt and Process substitution.
When using the prompt method, specifying the password should be followed with
a return and ctrl+d so it becomes equivalent to a string password. As an example,
tpm2_tool -p str:password is equivalent to tpm2_tool -p -, followed by
prompt:password<return><ctrl+d>

By default passwords are assumed to be in the string form. Password form is
specified with special prefix values, they are:

  * str:<password> Used to indicate it is a raw string. Useful for escaping a
                   password that starts with the "hex:" prefix.
  * hex:<password> Used when specifying a password in hex string format.
  * file:<file>    Used when specifying a password stored in a file. Useful to
                   prevent leaking the password to UNIX utilities (such as ps).
  * "-"            Used when specifying a password from stdin. There are 2 ways
                   to specify the password. A prompt and by the process
                   substitution method. Note that this is is similar to using
                   file:-, however this option additionally hides password
                   characters being echoed back to screen when using prompt.

## Sessions

When using a policy session to authorize the use of an object, prefix the option argument
with the *session* keyword.  Then indicate a path to a session file that was created
with tpm2_startauthsession(1). Optionally, if the session requires an auth value to be
sent with the session handle (eg policy password), then append a + and a string as described
in the **Passwords** section.

## PCR Authorizations

You can satisfy a PCR policy using the "pcr:" prefix and the PCR minilanguage. The PCR
minilanguage is as follows:
`<pcr-spec>+<raw-pcr-file>`

The PCR spec is documented in in the section "PCR bank specifiers".

The `raw-pcr-file` is an **optional** the output of the raw PCR contents as returned by *tpm2_pcrlist(1)*.

[PCR bank specifiers](common/pcr.md)

### Examples

To use the password `mypassword`:
```
mypassword
```

To use a raw binary password of 0x112233 in hex string format:
```
hex:112233
```

To use a password of `hex:` use the str escape:
```
str:hex:
```

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

To use stdin method of specifying the password.
```
echo $password | tpm2_tool -p -
```

To use stdin method of specifying the password with process substitution.
```
tpm2_tool -p - <<< $password
```
