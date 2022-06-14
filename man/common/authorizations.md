# Authorization Formatting

Authorization for use of an object in TPM2.0 can come in 3 different forms:
1. Password
2. HMAC
3. Sessions

**NOTE:** "Authorizations default to the **EMPTY PASSWORD** when not specified".

## Passwords

Passwords are interpreted in the following forms below using prefix identifiers.

**Note**: By default passwords are assumed to be in the string form when they do
not have a prefix.

### String

A string password, specified by prefix "str:" or it's absence
(raw string without prefix) is not interpreted, and is directly used for
authorization.

#### Examples

```
foobar
str:foobar
```

### Hex-string

A hex-string password, specified by prefix "hex:" is converted from a hexidecimal
form into a byte array form, thus allowing passwords with non-printable and/or
terminal un-friendly characters.

#### Example
```
hex:1122334455667788
```

### File

A file based password, specified be prefix "file:" should be the path of a file
containing the password to be read by the tool or a "-" to use stdin.
Storing passwords in files prevents information leakage, passwords passed as
options can be read from the process list or common shell history features.

#### Examples

```
# to use stdin and be prompted
file:-

# to use a file from a path
file:path/to/password/file

# to echo a password via stdin:
echo foobar | tpm2_tool -p file:-

# to use a bash here-string via stdin:

tpm2_tool -p file:- <<< foobar
```

## Sessions

When using a policy session to authorize the use of an object, prefix the option argument
with the *session* keyword.  Then indicate a path to a session file that was created
with tpm2_startauthsession(1). Optionally, if the session requires an auth value to be
sent with the session handle (eg policy password), then append a + and a string as described
in the **Passwords** section.

### Examples
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

## PCR Authorizations

You can satisfy a PCR policy using the "pcr:" prefix and the PCR minilanguage. The PCR
minilanguage is as follows:
`<pcr-spec>=<raw-pcr-file>`

The PCR spec is documented in in the section "PCR bank specifiers".

The `raw-pcr-file` is an **optional** argument that contains the output of the raw PCR contents as returned by *tpm2_pcrread(1)*.

[PCR bank specifiers](pcr.md)

### Examples

To satisfy a PCR policy of sha256 on banks 0, 1, 2 and 3 use a specifier of:
```
pcr:sha256:0,1,2,3
```
