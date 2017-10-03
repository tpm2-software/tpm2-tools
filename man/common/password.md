# Password Formatting

Passwords are interpreted in two forms, string and hex-string. A string password is not
interpreted, and is directly used for authorization. A hex-string, is converted from
a hexidecimal form into a byte array form, thus allowing passwords with non-printable
and/or terminal un-friendly characters.

By default passwords are assumed to be in the string form. Password form is specified
with special prefix values, they are:

  * str: - Used to indicate it is a raw string. Useful for escaping a password that starts
         with the "hex:" prefix.
  * hex: - Used when specifying a password in hex string format.
