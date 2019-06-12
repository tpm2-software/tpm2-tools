# Context Object Format

The type of a context object, whether it is a handle or file name, is
determined according to the following logic *in-order*:

  * If the argument is a file path, then the file is loaded as a restored TPM transient object.

  * If the argument is a *prefix* match on one of:
    * owner: the owner hierarchy
    * platform: the platform hierarchy
    * endorsement: the endorsement hierarchy
    * lockout: the lockout control persistent object

  * If the argument argument can be loaded as a number it will be treat as a handle,
    e.g. 0x81010013 and used directly.