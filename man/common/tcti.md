# TCTI ENVIRONMENT

This collection of environment variables that may be used to configure the
various TCTI modules available.

The values passed through these variables can be overridden on a per-command
basis using the available command line options, see the _TCTI_OPTIONS_ section.

The variables respected depend on how the software was configured.

  * _TPM2TOOLS\_TCTI\_NAME_:
	Select the TCTI used for communication with the next component down the TSS
	stack. In most configurations this will be the Resource Manager called tabrmd,
	but it could be a TPM simulator or TPM device itself.

  The current known TCTIs are:

	* tabrmd - The new resource manager, called
	           [tabrmd](https://github.com/tpm2-software/tpm2-abrmd).
	           Note that tabrmd and abrmd as a tcti name are synonymous.
	* mssim  - Typically used for communicating to the TPM software simulator.
	* device - Used when talking directly to a TPM device file.

One can pass TCTI specific options to a TCTI via the _TPM2TOOLS\_TCTI\_NAME_ environment
variable by appending the option string after the name with a : (colon) separator. These TCTI
option config strings are TCTI specific. Specifying **-h** on the tool command line will
show help output for the TCTIs. The section **TCTI OPTIONS** has examples for known TCTIs.

Formally, the format is:
`<tcti-name>:<tcti-option-config>`


Specifying an empty string for either the `<tcti-name>` or `<tcti-option-config>`
results in the default being used for that portion respectively.

# TCTI OPTIONS

This collection of options are used to configure the various TCTI modules
available. They override any environment variables.

  * **-T**, **--tcti**=_TCTI\_NAME_[:_TCTI\_OPTIONS_]:
	Select the TCTI used for communication with the TPM. This is a two part option, with
	_TCTI\_NAME_ being the name of the TCTI to be used. This can be a friendly name (-T mssim), a
	library name (libtss2-tcti-mssim.so) or a path (/foo/bar/libtss2-tcti-mssim.so).
	Optionally, tcti specific options can appended to _TCTI\_NAME_ by appending 	a **:** to
	_TCTI\_NAME_. There are 3 known TCTIs, and their name and options are defined below:

    * **device**: For the device TCTI, the TPM character device file for use by the device TCTI
      can be specified. The default is /dev/tpm0.
      Example: **-T device:/dev/tpm0** or **export _TPM2TOOLS\_TCTI\_NAME_="device:/dev/tpm0"**

    * **mssim**: For the mssim TCTI, the domain name or IP address and port number used by the simulator
      can be specified. The default are 127.0.0.1 and 2321.
      Example: **-T mssim:tcp://127.0.0.1:2321** or **export _TPM2TOOLS\_TCTI\_NAME_="mssim:tcp://127.0.0.1:2321"**

    * **abrmd**: For the abrmd TCTI, the configuration string format is a series of simple key value pairs
      separated by a ',' character. Each key and value string are separated by a '=' character.

        * TCTI abrmd supports two keys:
            1. 'bus_name' : The name of the tabrmd service on the bus (a string).
            2. 'bus_type' : The type of the dbus instance (a string) limited to
               'session' and 'system'.

        Specify the tabrmd tcti name and a config string of ```bus_name=com.example.FooBar```:
        ```
        --tcti=tabrmd:bus_name=com.example.FooBar
        ```

        Specify the default (abrmd) tcti and a config string of ```bus_type=session```:
        ```
        --tcti:bus_type=session
        ```

        Specify the device tcti and use the default config:
        ```
        --tcti=device
        ```
        or
        ```
        --tcti=device:
        ```

        **NOTE**: abrmd and tabrmd are synonymous.

## TCTI Defaults
When a TCTI is not specified, the default TCTI is searched for using dlopen(3) semantics.
The tools will search for *tabrmd*, *device* and *mssim* TCTIs **IN THAT ORDER** and
**USE THE FIRST ONE FOUND**. You can query what TCTI will be chosen as the default by
using the `-v` option to print the version information. The "default-tcti" key-value pair
will indicate which of the aforementioned TCTIs is the default.
