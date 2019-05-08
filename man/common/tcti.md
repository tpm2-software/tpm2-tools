# TCTI Configuration

The TCTI or "Transmission Interface" is the communication mechanism with the
TPM. TCTIs can be changed for communication with TPMs across different
mediums.

To control the TCTI, the tools respect:

  1. The command line option **-T** or **\--tcti**
  2. The environment variable: _TPM2TOOLS\_TCTI_.

**Note:** The command line option always overrides the environment variable.

The current known TCTIs are:

  * tabrmd - The resource manager, called
             [tabrmd](https://github.com/tpm2-software/tpm2-abrmd).
	           Note that tabrmd and abrmd as a tcti name are synonymous.

  * mssim  - Typically used for communicating to the TPM software simulator.

  * device - Used when talking directly to a TPM device file.

  * none - Do not initalize a connection with the TPM. Some tools allow for off-tpm
           options and thus support not using a TCTI. Tools that do not support it
           will error when attempted to be used without a TCTI connection. Does not
           support *ANY* options and *MUST BE* presented as the exact text of "none".

The arguments to either the command line option or the environment variable are
in the form:

`<tcti-name>:<tcti-option-config>`

Specifying an empty string for either the `<tcti-name>` or
`<tcti-option-config>` results in the default being used for that portion
respectively.

## TCTI Defaults

When a TCTI is not specified, the default TCTI is searched for using *dlopen(3)*
semantics. The tools will search for *tabrmd*, *device* and *mssim* TCTIs
**IN THAT ORDER** and **USE THE FIRST ONE FOUND**. You can query what TCTI will
be chosen as the default by using the **-v** option to print the version
information. The "default-tcti" key-value pair will indicate which of the
aforementioned TCTIs is the default.

## Custom TCTIs

Any TCTI that implements the dynamic TCTI interface can be loaded. The tools
internally use *dlopen(3)*, and the raw *tcti-name* value is used for the
lookup. Thus, this could be a path to the shared library, or a library name as
understood by *dlopen(3)* semantics.


# TCTI OPTIONS

This collection of options are used to configure the various known TCTI modules
available:

  * **device**:
    For the device TCTI, the TPM character device file for use by
    the device TCTI can be specified. The default is */dev/tpm0*.

    Example: **-T device:/dev/tpm0** or
    **export _TPM2TOOLS\_TCTI_="device:/dev/tpm0"**

  * **mssim**:
    For the mssim TCTI, the domain name or IP address and port number used by
    the simulator can be specified. The default are 127.0.0.1 and 2321.

    Example: **-T mssim:host=localhost,port=2321** or
    **export _TPM2TOOLS\_TCTI_="mssim:host=localhost,port=2321"**

  * **abrmd**:
    For the abrmd TCTI, the configuration string format is a series of simple
    key value pairs separated by a ',' character. Each key and value string
    are separated by a '=' character.

      * TCTI abrmd supports two keys:

          1. 'bus_name' : The name of the tabrmd service on the bus (a string).
          2. 'bus_type' : The type of the dbus instance (a string) limited to
               'session' and 'system'.

      Specify the tabrmd tcti name and a config string of
      ```bus_name=com.example.FooBar```:

      ```
      \--tcti=tabrmd:bus_name=com.example.FooBar
      ```

      Specify the default (abrmd) tcti and a config string of
      ```bus_type=session```:

      ```
      \--tcti:bus_type=session
      ```

      **NOTE**: abrmd and tabrmd are synonymous.
